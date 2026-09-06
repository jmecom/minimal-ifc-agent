# minimal ifc agent

Minimal agent, inspired by [Gollum](https://github.com/ddz/gollum), that implements information flow control.

The tools are `read(path)`, `write(path, content)`, `edit(path, old, new)`,
`shell(command)`, `inspect(ref)`, and `query_llm(ref, query)`.
File operations use UTF-8. `write` creates or overwrites a file;
`edit` requires a nonempty `old` string that occurs exactly once.

`read` stores the file contents in the global `HIDDEN_VARIABLES` dictionary and
returns a handle such as `{"ref":"v1"}`. Each entry holds the text and its `Label`.
Every file-tool argument accepts literal text or an exact reference object:

```text
read(path="original.txt")                          -> {"ref":"v1"}
write(path="copy.txt", content={"ref":"v1"})       -> Written.
edit(path="copy.txt", old="hello", new="goodbye")  -> Edited.
```

The model sees the handle until it calls `inspect`. References remain available across
turns until the process exits. The string `"v1"` is literal text; references are
never expanded inside strings or recursively inside stored values. References
are resolved and edit matches are checked before any file is changed.

`inspect(ref="v1")` returns the stored text to the main model. The conversation
takes on its label: inspecting untrusted text makes the conversation untrusted.

`query_llm(ref="v1", query="Summarize this")` sends the query and stored text to a
separate OpenAI request using the same `OPENAI_MODEL`. That request has no tools
and no main conversation history. Its answer is stored under a new reference,
with the combined labels of the input value and the current conversation.
The main model sees only the new reference until it calls `inspect` on it.

```text
read(path="original.txt")                         -> {"ref":"v1"}
query_llm(ref="v1", query="Summarize this")        -> {"ref":"v2"}
write(path="summary.txt", content={"ref":"v2"})  -> Written.
inspect(ref="v2")                                -> the summary text
```

The helper returns plain text. It can produce a bad summary or follow injected
instructions, so processing untrusted data does not make its output trusted.
Private text is sent to OpenAI when the helper processes it; hiding a value keeps
it out of the main conversation, not out of every model request.

The CLI separates tool calls into small boxes, with colored `You` and `Assistant`
labels. Run `.venv/bin/python agent.py --debug` to include dim IFC labels:

```text
┌─ read
│ input: {"path": "agent.py"}
│ [ifc] conversation before  confidentiality=public  integrity=trusted
│ [ifc] stored v1  confidentiality=private  integrity=untrusted
│ output: {"ref": "v1"}
│ [ifc] conversation after  confidentiality=private  integrity=trusted
└─

Assistant
The file is stored as reference v1.
```

Tool activity goes to stderr; assistant replies go to stdout. Debug lines show
references and labels, without hidden contents. Redirected output uses plain
text; set `NO_COLOR=1` to disable terminal colors.

The conversation label lives alongside its history and starts public/trusted.
Each tool response contributes a label: combining labels keeps either private or
untrusted once present. Later user messages and assistant replies do not reset it.

Reads store private/untrusted text behind references. Following Microsoft's
conservative accounting, these hidden results raise the conversation's
confidentiality to private while preserving its integrity. Shell output is
visible and labeled private/untrusted because commands can read arbitrary files.
Fixed write/edit acknowledgments and sanitized file errors are public/trusted;
they cannot lower an existing conversation label.

This step tracks labels only. Tool-policy checks are still to come. Shell output
is still visible, and commands retain ordinary host access; this is not an IFC sandbox.
