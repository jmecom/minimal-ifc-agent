# Minimal Python agent

One file, one dependency, one tool. Inspired by [Gollum](https://github.com/ddz/gollum).

The agent sends your message to OpenAI, runs any requested shell commands, and
feeds their output back to the model until it answers. Conversation history stays
in memory until you quit. The loop uses the
[OpenAI Responses API](https://developers.openai.com/api/docs/guides/function-calling).

```sh
cd ~/development/minimal-ifc-agent
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
export OPENAI_API_KEY='your-key'
.venv/bin/python agent.py
```

Try `List the files in this directory`, then ask a follow-up. Type `/quit` or press
Ctrl-D to exit; Ctrl-C stops the agent.

Defaults to `gpt-5.4-mini`; set `OPENAI_MODEL` to change it.

Shell commands run directly with your user permissions and can read or change
files. Each call starts in the directory where you launched the agent; `cd` and
environment changes do not persist between calls. Commands have a 60-second timeout.
