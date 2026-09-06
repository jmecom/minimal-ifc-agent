import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from itertools import count
from pathlib import Path

from openai import OpenAI


class Confidentiality(Enum):
    PUBLIC = "public"
    PRIVATE = "private"


class Integrity(Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Label:
    confidentiality: Confidentiality
    integrity: Integrity


@dataclass(frozen=True)
class HiddenVariable:
    value: str
    label: Label


HIDDEN_VARIABLES: dict[str, HiddenVariable] = {}
VARIABLE_IDS = count(1)


def color(text, style, *, stream=None):
    stream = sys.stdout if stream is None else stream
    if stream.isatty() and not os.environ.get("NO_COLOR"):
        return f"\033[{style}m{text}\033[0m"
    return text


def tool_line(text):
    for line in text.splitlines():
        print(color("│ ", "2;90", stream=sys.stderr) + line, file=sys.stderr, flush=True)


def debug_label(event, reference, label):
    confidentiality_color = "2;35" if label.confidentiality == Confidentiality.PRIVATE else "2;36"
    integrity_color = "2;33" if label.integrity == Integrity.UNTRUSTED else "2;32"
    tool_line(
        color(f"[ifc] {event} {reference}  ", "2", stream=sys.stderr)
        + color(f"confidentiality={label.confidentiality.value}  ", confidentiality_color, stream=sys.stderr)
        + color(f"integrity={label.integrity.value}", integrity_color, stream=sys.stderr)
    )


def hide(value, label, *, debug=False):
    reference = f"v{next(VARIABLE_IDS)}"
    HIDDEN_VARIABLES[reference] = HiddenVariable(value, label)
    if debug:
        debug_label("stored", reference, label)
    return {"ref": reference}


def resolve(value, *, debug=False):
    if isinstance(value, str):
        return value
    if not isinstance(value, dict) or set(value) != {"ref"} or not isinstance(value["ref"], str):
        raise ValueError('Expected literal text or a reference like {"ref":"v1"}.')
    if value["ref"] not in HIDDEN_VARIABLES:
        raise ValueError(f"Unknown reference: {value['ref']}")
    variable = HIDDEN_VARIABLES[value["ref"]]
    if debug:
        debug_label("resolved", value["ref"], variable.label)
    return variable.value


TEXT_OR_REF = {
    "description": "Literal text or a hidden-variable reference returned by read.",
    "anyOf": [
        {"type": "string"},
        {
            "type": "object",
            "properties": {"ref": {"type": "string"}},
            "required": ["ref"],
            "additionalProperties": False,
        },
    ],
}


def tool_schema(name, description, **parameters):
    return {
        "type": "function",
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": parameters,
            "required": list(parameters),
            "additionalProperties": False,
        },
        "strict": True,
    }


TOOLS = [
    tool_schema(
        "shell",
        "Run a bash command in a fresh shell in the agent's working directory.",
        command={"type": "string"},
    ),
    tool_schema(
        "read", "Read a UTF-8 file into a hidden variable. Returns a reference, not its contents.",
        path=TEXT_OR_REF,
    ),
    tool_schema(
        "write", "Create or overwrite a UTF-8 file with literal or referenced content.",
        path=TEXT_OR_REF, content=TEXT_OR_REF,
    ),
    tool_schema(
        "edit", "Replace exactly one occurrence of old with new in a UTF-8 file. old must not be empty.",
        path=TEXT_OR_REF, old=TEXT_OR_REF, new=TEXT_OR_REF,
    ),
]


def read(path, *, debug=False):
    value = Path(resolve(path, debug=debug)).read_bytes().decode("utf-8")
    # Until file labeling is configured, treat every read as private and untrusted.
    return hide(value, Label(Confidentiality.PRIVATE, Integrity.UNTRUSTED), debug=debug)


def write(path, content, *, debug=False):
    Path(resolve(path, debug=debug)).write_bytes(resolve(content, debug=debug).encode("utf-8"))
    return "Written."


def edit(path, old, new, *, debug=False):
    path = Path(resolve(path, debug=debug))
    old, new = resolve(old, debug=debug), resolve(new, debug=debug)
    if not old:
        raise ValueError("old must not be empty.")
    value = path.read_bytes().decode("utf-8")
    if value.count(old) != 1:
        raise ValueError("old must occur exactly once; the file was not changed.")
    path.write_bytes(value.replace(old, new, 1).encode("utf-8"))
    return "Edited."


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
        return f"Exit code: {result.returncode}\n{result.stdout}"
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 60 seconds."


TOOL_FUNCTIONS = {"read": read, "write": write, "edit": edit, "shell": shell}


def run_tool(name, arguments, *, debug=False):
    try:
        if name not in TOOL_FUNCTIONS:
            raise ValueError(f"Unknown tool: {name}")
        if name == "shell":
            result = shell(**arguments)
        else:
            result = TOOL_FUNCTIONS[name](**arguments, debug=debug)
        return json.dumps(result) if isinstance(result, dict) else result
    except (OSError, UnicodeError) as error:
        # File errors can contain paths or bytes obtained from hidden variables.
        return f"Error: {type(error).__name__}"
    except (TypeError, ValueError) as error:
        return f"Error: {error}"


def main():
    parser = argparse.ArgumentParser(description="Minimal agent with hidden-variable references.")
    parser.add_argument(
        "--debug", action="store_true",
        help="Show IFC labels when hidden variables are stored or resolved.",
    )
    debug = parser.parse_args().debug
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("Set OPENAI_API_KEY before running the agent.")
    client = OpenAI()
    history = []

    while True:
        prompt = input(color("\nYou: ", "1;32")).strip()
        if prompt == "/quit":
            return
        if not prompt:
            continue
        history.append({"role": "user", "content": prompt})

        while True:
            response = client.responses.create(
                model=os.environ.get("OPENAI_MODEL", "gpt-5.4-mini"),
                instructions=(
                    "You are a helpful coding agent. Use read, write, and edit for file operations, "
                    "and shell for commands. read returns a hidden-variable reference such as "
                    '{"ref":"v1"}. Pass that object as a file-tool argument to reuse its text. '
                    'The string "v1" is literal text, not a reference. '
                    "You cannot infer a hidden value's contents from its reference."
                ),
                tools=TOOLS,
                input=history,
            )
            history.extend(response.output)
            if response.output_text:
                print(f"\n{color('Assistant', '1;36')}\n{response.output_text}", flush=True)
            calls = [item for item in response.output if item.type == "function_call"]
            if not calls:
                break
            for call in calls:
                arguments = json.loads(call.arguments)
                print(color(f"\n┌─ {call.name}", "2;36", stream=sys.stderr), file=sys.stderr, flush=True)
                tool_line(f"input: {json.dumps(arguments, ensure_ascii=False)}")
                output = run_tool(call.name, arguments, debug=debug)
                tool_line(f"output: {output}")
                print(color("└─", "2;36", stream=sys.stderr), file=sys.stderr, flush=True)
                history.append({
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": output,
                })


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print()
