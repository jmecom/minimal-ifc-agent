import argparse
import json
import logging
import os
import sys
from pathlib import Path

from openai import OpenAI

import agent_core as core


def color(text, style, *, stream=None):
    stream = sys.stdout if stream is None else stream
    if stream.isatty() and not os.environ.get("NO_COLOR"):
        return f"\033[{style}m{text}\033[0m"
    return text


def tool_line(text):
    for line in text.splitlines():
        print(color("│ ", "2;90", stream=sys.stderr) + line, file=sys.stderr, flush=True)


def tool_border(text):
    print(color(text, "2;36", stream=sys.stderr), file=sys.stderr, flush=True)


class LabelHandler(logging.Handler):
    def emit(self, record):
        label = record.label
        confidentiality_color = "2;35" if label.confidentiality == core.Confidentiality.PRIVATE else "2;36"
        integrity_color = "2;33" if label.integrity == core.Integrity.UNTRUSTED else "2;32"
        tool_line(
            color(f"[ifc] {record.getMessage()}  ", "2", stream=sys.stderr)
            + color(f"confidentiality={label.confidentiality.value}  ", confidentiality_color, stream=sys.stderr)
            + color(f"integrity={label.integrity.value}", integrity_color, stream=sys.stderr)
        )


def approve_read(path):
    tool_line(f"Read outside workspace: {json.dumps(str(path))}")
    tool_line("[d] Deny (default)")
    tool_line("[u] Read as untrusted. The conversation becomes untrusted; edits and shell are blocked.")
    tool_line("[t] Trust this read. Keep the conversation's current trust.")
    tool_line("Both reads stay private. Trusting this read does not clear earlier untrusted input.")

    while True:
        try:
            choice = input(color("│ Choose [d/u/t] (d): ", "2;33")).strip().lower()
        except EOFError:
            choice = "d"

        if choice in ("", "d", "deny"):
            raise core.PolicyError("Outside read denied by user.")
        if choice in ("u", "untrusted"):
            return core.PRIVATE_UNTRUSTED
        if choice in ("t", "trust"):
            return core.PRIVATE_TRUSTED
        tool_line("Choose d, u, or t.")


def chat(agent, *, debug=False):
    client = OpenAI()
    handler = LabelHandler()
    previous_level = core.LOG.level
    core.LOG.setLevel(logging.DEBUG if debug else logging.WARNING)
    core.LOG.addHandler(handler)

    try:
        while True:
            prompt = input(color("\nYou: ", "1;32")).strip()
            if prompt == "/quit":
                return
            if not prompt:
                continue

            for event in agent.respond(prompt, client):
                if isinstance(event, str):
                    print(f"\n{color('Assistant', '1;36')}\n{event}", flush=True)
                elif isinstance(event, core.ToolCall):
                    tool_border(f"\n┌─ {event.name}")
                    tool_line(f"input: {json.dumps(event.arguments, ensure_ascii=False)}")
                    core.trace("conversation", "before", agent.conversation_label)
                else:
                    assert isinstance(event, core.LabeledValue), "Expected a tool result."
                    output = event.value
                    if output.startswith("Blocked by IFC:"):
                        output = color(output, "2;31", stream=sys.stderr)
                    tool_line(f"output: {output}")
                    core.trace("conversation", "after", agent.conversation_label)
                    tool_border("└─")
    finally:
        core.LOG.removeHandler(handler)
        core.LOG.setLevel(previous_level)


def parse_arguments(description, *, workspace=False):
    parser = argparse.ArgumentParser(description=description)
    if workspace:
        parser.add_argument(
            "--workspace", required=True, type=Path,
            help="Approve this directory's contents and allow sandboxed edits in place.",
        )
    parser.add_argument("--debug", action="store_true", help="Show IFC labels during tool calls.")
    arguments = parser.parse_args()
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("Set OPENAI_API_KEY before running the agent.")
    return arguments


def run(main):
    try:
        main()
    except core.PolicyError as error:
        print(color(f"Blocked by IFC: {error}", "2;31", stream=sys.stderr), file=sys.stderr)
    except (EOFError, KeyboardInterrupt):
        print()
