import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
from functools import partial
from pathlib import Path

import agent_core as core
import agent_ui as ui


class Sandbox:
    def __init__(self, workspace):
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
            raise ValueError("This agent requires macOS sandbox-exec. There is no unsandboxed fallback.")

        self.workspace = Path(workspace).expanduser().resolve(strict=True)
        if not self.workspace.is_dir():
            raise ValueError("Workspace must be a directory.")

        runtime_paths = {
            Path("/bin"), Path("/usr/bin"), Path("/usr/lib"), Path("/System/Library"),
            Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve(),
        }
        def fail_scan(error):
            raise error

        for directory, _, names in os.walk(self.workspace, followlinks=False, onerror=fail_scan):
            for name in names:
                info = (Path(directory) / name).lstat()
                if stat.S_ISLNK(info.st_mode) or stat.S_ISSOCK(info.st_mode):
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError("Workspace files must be regular files without hard links, or symlinks. Found: " + str(Path(directory) / name))

        self.temporary_directory = tempfile.TemporaryDirectory(prefix="minimal-ifc-")
        self.scratch = Path(self.temporary_directory.name).resolve()
        if self.scratch.is_relative_to(self.workspace):
            self.close()
            raise ValueError("The workspace cannot contain the agent's temporary directory.")

        readable = runtime_paths | {self.workspace, self.scratch}
        ancestors = {parent for path in readable for parent in path.parents}

        self.profile = "\n".join([
            "(version 1)",
            "(deny default)",
            '(import "/System/Library/Sandbox/Profiles/dyld-support.sb")',
            "(allow process-exec process-fork)",
            "(allow signal (target same-sandbox))",
            "(allow process-info* (target same-sandbox))",
            '(allow sysctl-read (sysctl-name "hw.ncpu") (sysctl-name "hw.pagesize") '
            '(sysctl-name "hw.memsize") (sysctl-name "hw.machine") '
            '(sysctl-name "kern.osrelease") (sysctl-name "kern.ostype") '
            '(sysctl-name "kern.version") (sysctl-name "kern.hostname"))',
            '(allow file-read* (literal "/dev/null") (literal "/dev/urandom"))',
            '(allow file-write-data (literal "/dev/null"))',
            *(f"(allow file-read* (subpath {json.dumps(str(path), ensure_ascii=False)}))" for path in sorted(readable)),
            *(f"(allow file-read-metadata (literal {json.dumps(str(path), ensure_ascii=False)}))" for path in sorted(ancestors)),
            *(f"(allow file-write* (subpath {json.dumps(str(path), ensure_ascii=False)}))" for path in (self.workspace, self.scratch)),
        ])

        self.environment = {
            "PATH": f"{Path(sys.prefix) / 'bin'}:{Path(sys.base_prefix) / 'bin'}:/usr/bin:/bin",
            "HOME": str(self.scratch),
            "TMPDIR": str(self.scratch),
            "LANG": "en_US.UTF-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        result = self.run([sys.executable, "-I", "-S", "-c", "print('sandbox ready')"])
        if result.returncode != 0 or result.stdout.strip() != "sandbox ready":
            self.close()
            raise ValueError(f"Sandbox startup failed (exit {result.returncode}): {result.stdout.strip()}")

    def close(self):
        self.temporary_directory.cleanup()

    def run(self, command, *, payload=None, timeout=60, allowed_read=None):
        profile = self.profile
        if allowed_read is not None:
            profile += f"\n(allow file-read* (literal {json.dumps(str(allowed_read), ensure_ascii=False)}))"
            profile += "".join(
                f"\n(allow file-read-metadata (literal {json.dumps(str(parent), ensure_ascii=False)}))"
                for parent in allowed_read.parents
            )

        process = subprocess.Popen(
            ["/usr/bin/sandbox-exec", "-p", profile, *command],
            cwd=self.workspace,
            env=self.environment,
            stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            close_fds=True,
            start_new_session=True,
        )

        try:
            output, _ = process.communicate(payload, timeout=timeout)
            return subprocess.CompletedProcess(command, process.returncode, output)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            if process.stdin is not None:
                process.stdin.close()


FILE_WORKER = """
import json
import sys
from pathlib import Path

try:
    operation, arguments = json.load(sys.stdin)
    path = Path(arguments["path"]).resolve()
    if not path.is_relative_to(Path.cwd()):
        raise ValueError("Path must be inside the approved workspace.")

    if operation == "read":
        value = path.read_bytes().decode("utf-8")
    elif operation == "write":
        path.write_bytes(arguments["content"].encode("utf-8"))
        value = "Written."
    elif operation == "edit":
        old, new = arguments["old"], arguments["new"]
        if not old:
            raise ValueError("old must not be empty.")
        value = path.read_bytes().decode("utf-8")
        if value.count(old) != 1:
            raise ValueError("old must occur exactly once; the file was not changed.")
        path.write_bytes(value.replace(old, new, 1).encode("utf-8"))
        value = "Edited."
    else:
        raise ValueError("Unknown file operation.")

    print(json.dumps({"value": value}))
except (OSError, UnicodeError) as error:
    print(json.dumps({"error": type(error).__name__}))
except ValueError as error:
    print(json.dumps({"error": str(error)}))
"""


def file_operation(operation, arguments, *, sandbox):
    result = sandbox.run(
        [sys.executable, "-I", "-S", "-c", FILE_WORKER],
        payload=json.dumps([operation, arguments]),
    )

    if result.returncode != 0:
        raise ValueError("Sandboxed file operation failed.")

    output = json.loads(result.stdout)
    if "error" in output:
        raise ValueError(output["error"])

    return core.LabeledValue(output["value"], core.PRIVATE_TRUSTED)


def read(path, *, sandbox):
    path = (sandbox.workspace / Path(path).expanduser()).resolve()
    if path.is_relative_to(sandbox.workspace):
        return file_operation("read", {"path": str(path)}, sandbox=sandbox)

    label = ui.approve_read(path)
    result = sandbox.run(
        [sys.executable, "-I", "-S", "-c", APPROVED_READ, str(path)],
        allowed_read=path,
    )
    if result.returncode != 0:
        raise ValueError("Approved outside read failed; only regular UTF-8 files can be read.")

    core.trace("approved read", json.dumps(str(path)), label)

    return core.LabeledValue(json.loads(result.stdout)["value"], label, expose=True)


APPROVED_READ = """
import json
import os
import stat
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(descriptor, "rb") as source:
    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
        raise ValueError("Only regular files can be read.")
    value = source.read().decode("utf-8")

print(json.dumps({"value": value}))
"""


def write(path, content, *, sandbox):
    return file_operation("write", {"path": path, "content": content}, sandbox=sandbox)


def edit(path, old, new, *, sandbox):
    return file_operation("edit", {"path": path, "old": old, "new": new}, sandbox=sandbox)


def shell(command, *, sandbox):
    result = sandbox.run(["/bin/bash", "--noprofile", "--norc", "-c", command])

    return core.LabeledValue(f"Exit code: {result.returncode}\n{result.stdout}", core.PRIVATE_TRUSTED)


TOOL_POLICIES = {
    "shell": {"command": core.PRIVATE_TRUSTED},
    "read": {"path": core.PRIVATE_UNTRUSTED},
    "write": {"path": core.PRIVATE_TRUSTED, "content": core.PRIVATE_TRUSTED},
    "edit": {"path": core.PRIVATE_TRUSTED, "old": core.PRIVATE_TRUSTED, "new": core.PRIVATE_TRUSTED},
    "inspect": {"ref": core.PRIVATE_UNTRUSTED},
    "quarantined_llm_call": {"ref": core.PRIVATE_UNTRUSTED, "query": core.PRIVATE_UNTRUSTED},
}


INSTRUCTIONS = (
    "You are a coding agent in an approved workspace. Use relative paths. File and shell tools run "
    "in a macOS sandbox: workspace/scratch writes, runtime reads, no network or access to other apps. "
    "Edits happen in place. Workspace reads and shell output are private/trusted and visible. "
    "Python and basic system commands are available; dependencies cannot be downloaded. "
    "Use read for outside files, including when shell cannot access them. The user chooses deny, "
    "untrusted, or trusted. Permission covers that read only; shell access stays unchanged. "
    "Both choices keep data private and preserve earlier taint. An untrusted read exposes the text "
    "and makes the conversation untrusted. write/edit require trusted paths and content; shell "
    "requires a trusted conversation. Reading untrusted text blocks later edits and shell calls. "
    "Untrusted references cannot be written into the workspace. You cannot approve reads or reset trust. "
    + core.REFERENCE_INSTRUCTIONS
)


def create_agent(sandbox):
    return core.Agent(
        tools=core.make_tools(
            shell_description="Run bash in the approved workspace, with no network or access to other projects. Returns exit code and output.",
            read_description="Read a UTF-8 file. Workspace contents are trusted; outside files require the user to allow the read and choose its trust label.",
        ),
        tool_functions={
            **core.REFERENCE_TOOLS,
            "read": partial(read, sandbox=sandbox),
            "write": partial(write, sandbox=sandbox),
            "edit": partial(edit, sandbox=sandbox),
            "shell": partial(shell, sandbox=sandbox),
        },
        tool_policies=TOOL_POLICIES,
        instructions=INSTRUCTIONS,
        inherit_call_integrity=True,
    )


def main():
    arguments = ui.parse_arguments("Coding agent in an approved, sandboxed workspace.", workspace=True)

    try:
        sandbox = Sandbox(arguments.workspace)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Cannot start sandbox: {error}") from error

    try:
        ui.chat(create_agent(sandbox), debug=arguments.debug)
    finally:
        sandbox.close()


if __name__ == "__main__":
    ui.run(main)
