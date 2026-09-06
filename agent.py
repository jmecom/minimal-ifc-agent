import json
import os
import subprocess

from openai import OpenAI


SHELL_TOOL = {
    "type": "function",
    "name": "shell",
    "description": (
        "Run a bash command to inspect or edit files and execute programs. "
        "Each call starts a fresh shell in the agent's working directory."
    ),
    "parameters": {
        "type": "object",
        "properties": {"command": {"type": "string"}},
        "required": ["command"],
        "additionalProperties": False,
    },
    "strict": True,
}


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
                instructions="You are a helpful coding agent. Use shell when needed to complete the user's task.",
                tools=[SHELL_TOOL],
                input=history,
            )
            history.extend(response.output)
            if response.output_text:
                print(response.output_text)
            calls = [item for item in response.output if item.type == "function_call"]
            if not calls:
                break
            for call in calls:
                output = shell(**json.loads(call.arguments))
                print(output)
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
