import subprocess
from pathlib import Path

import agent_core as core
import agent_ui as ui


def read(path):
    value = Path(path).read_bytes().decode("utf-8")

    return core.LabeledValue(value, core.PRIVATE_UNTRUSTED)


def write(path, content):
    Path(path).write_bytes(content.encode("utf-8"))

    return core.LabeledValue("Written.", core.PUBLIC_TRUSTED)


def edit(path, old, new):
    path = Path(path)
    if not old:
        raise ValueError("old must not be empty.")

    value = path.read_bytes().decode("utf-8")
    if value.count(old) != 1:
        raise ValueError("old must occur exactly once; the file was not changed.")

    path.write_bytes(value.replace(old, new, 1).encode("utf-8"))

    return core.LabeledValue("Edited.", core.PUBLIC_TRUSTED)


def shell(command):
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
    "You are a coding agent. Use read, write, and edit for files, and shell for commands. "
    "File reads and shell output are untrusted and hidden. write and edit require trusted paths, "
    "so an untrusted conversation cannot modify files. Shell requires a public, trusted conversation; "
    "reading a private file blocks shell. Complete changes before inspecting untrusted results. "
    + core.REFERENCE_INSTRUCTIONS
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
    arguments = ui.parse_arguments("Minimal agent with hidden-variable references.")
    ui.chat(create_agent(), debug=arguments.debug)


if __name__ == "__main__":
    ui.run(main)
