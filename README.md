# minimal ifc agent

Minimal agent, inspired by [Gollum](https://github.com/ddz/gollum), but that implements fides-style information flow control.

- [agent_basic.py](agent_basic.py): file reads and shell output are untrusted and hidden.
  Its shell has normal host access.
- [agent_useful_for_coding.py](agent_useful_for_coding.py): approves a project as
  private/trusted and edits it in place. File tools and shell run through macOS
  `sandbox-exec`, with workspace/scratch writes, runtime reads, and no network.

Both use [agent_core.py](agent_core.py) for the chat loop, labels, hidden
variables, and policy checks. Each agent supplies its tools and policies.

Set up the environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Set `OPENAI_API_KEY`; `OPENAI_MODEL` is optional. Run either agent:

```sh
.venv/bin/python agent_basic.py --debug
.venv/bin/python agent_useful_for_coding.py --workspace . --debug
```

`--debug` shows dim, colored IFC labels. `--workspace .` allows editing this
repo, including the agent itself. Type `/quit` to exit.

Tools: `read`, `write`, `edit`, `shell`, `inspect`, and `quarantined_llm_call`.
Untrusted values normally stay behind references. `inspect` exposes them and makes the
conversation untrusted; helper processing preserves their labels. The coding
agent's `/import PATH` command loads outside text as an untrusted reference,
which cannot be written into the approved workspace.

Outside `read` calls ask you to deny, read as untrusted (blocking later edits and
shell calls), or trust that read. Both reads stay private. Approval grants one
file read; it does not expand shell access or clear earlier untrusted input.

This is a research playground. The coding agent trusts the approved tree and
host; it does not track another process putting outside content into that tree.
OpenAI is allowed to receive private data. The sandbox limits access, but does
not prevent bad edits within the project.

Papers:

- [FIDES: Securing AI Agents with Information-Flow Control](https://arxiv.org/abs/2505.23643)
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813)
- [Prudentia: Optimizing Agent Planning for Security and Autonomy](https://arxiv.org/abs/2602.11416)
- [Denning: A Lattice Model of Secure Information Flow (1976)](https://faculty.nps.edu/dedennin/publications/lattice76.pdf)
- [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837)
