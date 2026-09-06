import json
import os
import subprocess
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


def hide(value, label):
    reference = f"v{next(VARIABLE_IDS)}"
    HIDDEN_VARIABLES[reference] = HiddenVariable(value, label)
    return {"ref": reference}


def resolve(value):
    if isinstance(value, str):
        return value
    if not isinstance(value, dict) or set(value) != {"ref"} or not isinstance(value["ref"], str):
        raise ValueError('Expected literal text or a reference like {"ref":"v1"}.')
    if value["ref"] not in HIDDEN_VARIABLES:
        raise ValueError(f"Unknown reference: {value['ref']}")
    return HIDDEN_VARIABLES[value["ref"]].value


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


def read(path):
    value = Path(resolve(path)).read_bytes().decode("utf-8")
    # Until file labeling is configured, treat every read as private and untrusted.
    return hide(value, Label(Confidentiality.PRIVATE, Integrity.UNTRUSTED))


def write(path, content):
    Path(resolve(path)).write_bytes(resolve(content).encode("utf-8"))
    return "Written."


def edit(path, old, new):
    path = Path(resolve(path))
    old, new = resolve(old), resolve(new)
    if not old:
        raise ValueError("old must not be empty.")
    value = path.read_bytes().decode("utf-8")
    if value.count(old) != 1:
        raise ValueError("old must occur exactly once; the file was not changed.")
    path.write_bytes(value.replace(old, new, 1).encode("utf-8"))
    return "Edited."


def shell(command):
    print(f"$ {command}", flush=True)
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


def run_tool(name, arguments):
    try:
        if name not in TOOL_FUNCTIONS:
            raise ValueError(f"Unknown tool: {name}")
        result = TOOL_FUNCTIONS[name](**arguments)
        return json.dumps(result) if isinstance(result, dict) else result
    except (OSError, UnicodeError) as error:
        # File errors can contain paths or bytes obtained from hidden variables.
        return f"Error: {type(error).__name__}"
    except (TypeError, ValueError) as error:
        return f"Error: {error}"


def main():
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("Set OPENAI_API_KEY before running the agent.")
    client = OpenAI()
    history = []

    while True:
        prompt = input("You: ").strip()
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
                print(response.output_text)
            calls = [item for item in response.output if item.type == "function_call"]
            if not calls:
                break
            for call in calls:
                output = run_tool(call.name, json.loads(call.arguments))
                print(f"{call.name}: {output}")
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
