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


# Python can hold data that the model never sees. We track labels on that data
# and on the conversation separately. This playground currently records those
# labels; the policy checks that would restrict tool calls are still to come.


class Confidentiality(Enum):
    # Confidentiality describes restrictions on sharing the data.
    PUBLIC = "public"
    PRIVATE = "private"


class Integrity(Enum):
    # Integrity describes which sources may influence decisions. Even harmless
    # text from an unknown source can be UNTRUSTED.
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class Label:
    # These dimensions are independent: a private note can be trusted, while
    # a public webpage can be untrusted.
    confidentiality: Confidentiality
    integrity: Integrity


def combine_labels(first, second):
    # IFC calls this a "join": keep the more restrictive value on each axis.
    # PRIVATE/TRUSTED combined with PUBLIC/UNTRUSTED becomes PRIVATE/UNTRUSTED.
    return Label(
        Confidentiality.PRIVATE
        if Confidentiality.PRIVATE in (first.confidentiality, second.confidentiality)
        else Confidentiality.PUBLIC,
        Integrity.UNTRUSTED
        if Integrity.UNTRUSTED in (first.integrity, second.integrity)
        else Integrity.TRUSTED,
    )


@dataclass(frozen=True)
class HiddenVariable:
    value: str
    label: Label


# These labels belong to stored values. They do not attach permissions to the
# original files, so another tool can still read those files independently.
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
    # Only the generated reference goes back to the model. Instructions inside
    # the stored text cannot influence the model while that text stays hidden.
    reference = f"v{next(VARIABLE_IDS)}"
    HIDDEN_VARIABLES[reference] = HiddenVariable(value, label)
    if debug:
        debug_label("stored", reference, label)
    return {"ref": reference}


def resolve(value, *, debug=False):
    # Python expands references while executing a tool. Expansion alone does
    # not expose the text to the model; a tool would have to return it visibly.
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
    # Bash still has ordinary host access. Labeling its output afterward cannot
    # undo file changes or network requests made while the command was running.
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
    # Return the text for history and the label that text contributes. A future
    # policy check belongs before execution, where it can still block the call.
    # Fixed acknowledgments and sanitized errors introduce no untrusted text.
    message_label = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)
    try:
        if name not in TOOL_FUNCTIONS:
            raise ValueError(f"Unknown tool: {name}")
        if name == "shell":
            # Shell can read arbitrary files; use a conservative result label.
            message_label = Label(Confidentiality.PRIVATE, Integrity.UNTRUSTED)
            result = shell(**arguments)
        else:
            result = TOOL_FUNCTIONS[name](**arguments, debug=debug)
        if isinstance(result, dict):
            variable = HIDDEN_VARIABLES[result["ref"]]
            # The stored text keeps its own label. Its opaque reference adds no
            # untrusted text to the conversation, so it contributes TRUSTED
            # integrity. Microsoft's accounting still counts its confidentiality:
            # a hidden PRIVATE/UNTRUSTED value contributes PRIVATE/TRUSTED here.
            message_label = Label(variable.label.confidentiality, Integrity.TRUSTED)
            result = json.dumps(result)
    except (OSError, UnicodeError) as error:
        # File errors can contain paths or bytes obtained from hidden variables.
        result = f"Error: {type(error).__name__}"
    except (TypeError, ValueError) as error:
        result = f"Error: {error}"
    return result, message_label


def main():
    parser = argparse.ArgumentParser(description="Minimal agent with hidden-variable references.")
    parser.add_argument(
        "--debug", action="store_true",
        help="Show hidden-variable labels and the conversation label before and after tools.",
    )
    debug = parser.parse_args().debug
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("Set OPENAI_API_KEY before running the agent.")
    client = OpenAI()
    history = []
    # User input is assumed public/trusted in this playground. Keep this label
    # outside the prompt loop: a new user message does not remove old tool
    # results from the history that the model sees.
    conversation_label = Label(Confidentiality.PUBLIC, Integrity.TRUSTED)

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
            # Model replies inherit the conversation's label because they may
            # depend on anything already in history.
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
                if debug:
                    debug_label("conversation", "before", conversation_label)
                output, message_label = run_tool(call.name, arguments, debug=debug)
                tool_line(f"output: {output}")
                history.append({
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": output,
                })
                # Once untrusted text enters history, even a later "Written."
                # acknowledgment cannot make that history trusted again.
                conversation_label = combine_labels(conversation_label, message_label)
                if debug:
                    debug_label("conversation", "after", conversation_label)
                print(color("└─", "2;36", stream=sys.stderr), file=sys.stderr, flush=True)


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print()
