# minimal ifc agent

Minimal agent, inspired by [Gollum](https://github.com/ddz/gollum), that implements information flow control.

The tools are `read(path)`, `write(path, content)`, `edit(path, old, new)`, and
`shell(command)`. File operations use UTF-8. `write` creates or overwrites a file;
`edit` requires a nonempty `old` string that occurs exactly once.

`read` stores the file contents in the global `HIDDEN_VARIABLES` dictionary and
returns a handle such as `{"ref":"v1"}`. Each entry holds the text and its `Label`.
Every file-tool argument accepts literal text or an exact reference object:

```text
read(path="original.txt")                          -> {"ref":"v1"}
write(path="copy.txt", content={"ref":"v1"})       -> Written.
edit(path="copy.txt", old="hello", new="goodbye")  -> Edited.
```

The model sees the handle, not the contents. References remain available across
turns until the process exits. The string `"v1"` is literal text; references are
never expanded inside strings or recursively inside stored values. References
are resolved and edit matches are checked before any file is changed.

The CLI separates tool calls into small boxes, with colored `You` and `Assistant`
labels. Run `.venv/bin/python agent.py --debug` to include dim IFC labels:

```text
┌─ read
│ input: {"path": "agent.py"}
│ [ifc] stored v1  confidentiality=private  integrity=untrusted
│ output: {"ref": "v1"}
└─

Assistant
The file is stored as reference v1.
```

Tool activity goes to stderr; assistant replies go to stdout. Debug lines show
references and labels, without hidden contents. Redirected output uses plain
text; set `NO_COLOR=1` to disable terminal colors.

Reads currently receive a fixed private/untrusted label. Labels are stored with
hidden values; label propagation and policy enforcement are not implemented yet.
Shell output remains visible to the model, and shell commands have ordinary host
access. This is a playground for reference handling, not an IFC sandbox.
