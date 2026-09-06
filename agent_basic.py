import subprocess
from pathlib import Path

import agent_core as core


def read(path, *, debug=False):
    value = Path(core.resolve(path, debug=debug)).read_bytes().decode("utf-8")

    return core.LabeledValue(value, core.PRIVATE_UNTRUSTED)


def write(path, content, *, debug=False):
    Path(core.resolve(path, debug=debug)).write_bytes(core.resolve(content, debug=debug).encode("utf-8"))

    return core.LabeledValue("Written.", core.PUBLIC_TRUSTED)


def edit(path, old, new, *, debug=False):
    path = Path(core.resolve(path, debug=debug))
    old, new = core.resolve(old, debug=debug), core.resolve(new, debug=debug)

    if not old:
        raise ValueError("old must not be empty.")

    value = path.read_bytes().decode("utf-8")
    if value.count(old) != 1:
        raise ValueError("old must occur exactly once; the file was not changed.")

    path.write_bytes(value.replace(old, new, 1).encode("utf-8"))

    return core.LabeledValue("Edited.", core.PUBLIC_TRUSTED)


def shell(command, *, debug=False):
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=60,
        )

        return core.LabeledValue(f"Exit code: {result.returncode}\n{result.stdout}", core.PRIVATE_UNTRUSTED)
    except subprocess.TimeoutExpired:
        return core.LabeledValue("Error: command timed out after 60 seconds.", core.PRIVATE_UNTRUSTED)


TOOL_POLICIES = {
    "shell": {"command": core.PUBLIC_TRUSTED},
    "read": {"path": core.PRIVATE_UNTRUSTED},
    "write": {"path": core.PRIVATE_TRUSTED, "content": core.PRIVATE_UNTRUSTED},
    "edit": {"path": core.PRIVATE_TRUSTED, "old": core.PRIVATE_UNTRUSTED, "new": core.PRIVATE_UNTRUSTED},
    "inspect": {"ref": core.PRIVATE_UNTRUSTED},
    "quarantined_llm_call": {"ref": core.PRIVATE_UNTRUSTED, "query": core.PRIVATE_UNTRUSTED},
}


INSTRUCTIONS = (
    "You are a helpful coding agent. Use read, write, and edit for file operations, and shell for "
    "commands. Untrusted tool results are hidden behind references such as "
    + core.REFERENCE_INSTRUCTIONS
    + (
        "write and edit require trusted paths, so an untrusted conversation cannot modify files. Shell "
        "requires a public, trusted conversation. Reading a private file blocks shell. Complete file "
        "changes before inspecting untrusted results. "
    )
    + core.BLOCKED_INSTRUCTIONS
)


def create_agent():
    return core.Agent(
        tools=core.make_tools(
            shell_description="Run a bash command in a fresh shell. Returns a hidden reference to its exit code and output.",
            read_description="Read a UTF-8 file into a hidden variable. Returns a reference, not its contents.",
        ),
        tool_functions={
            **core.REFERENCE_TOOLS,
            "read": read,
            "write": write,
            "edit": edit,
            "shell": shell,
        },
        tool_policies=TOOL_POLICIES,
        instructions=INSTRUCTIONS,
    )


def main():
    arguments = core.parse_arguments("Minimal agent with hidden-variable references.")
    create_agent().chat(debug=arguments.debug)


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print()
