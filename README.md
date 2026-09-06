# minimal ifc agent

Minimal agent, inspired by [Gollum](https://github.com/ddz/gollum), for experimenting
with information flow labels and tool permissions. The implementation is in `agent.py`.

The tools are `read(path)`, `write(path, content)`, `edit(path, old, new)`,
`shell(command)`, `inspect(ref)`, and `quarantined_llm_call(ref, query)`.
File operations use UTF-8. `write` creates or overwrites a file;
`edit` requires a nonempty `old` string that occurs exactly once.

Each tool returns a `LabeledValue`: text and its `Label`. The shared
`prepare_result` helper hides untrusted results in the global `HIDDEN_VARIABLES`
dictionary and returns a handle such as `{"ref":"v1"}` to the main model.
Trusted results are returned directly. `inspect` explicitly skips hiding so it
can expose the stored text with its original label.

`read` and `shell` both return private/untrusted results, so their text is hidden.
Shell's exit code and stdout/stderr are stored together behind one reference.
Every file-tool argument accepts literal text or an exact reference object:

```text
read(path="original.txt")                          -> {"ref":"v1"}
write(path="copy.txt", content={"ref":"v1"})       -> Written.
edit(path="copy.txt", old="hello", new="goodbye")  -> Edited.
```

The `read` result contains only the handle. References remain available across
turns until the process exits. The string `"v1"` is literal text; references are
never expanded inside strings or recursively inside stored values. References
are resolved and edit matches are checked before any file is changed.

`inspect(ref="v1")` returns the stored text to the main model. The conversation
takes on its label: inspecting untrusted text makes the conversation untrusted
and blocks subsequent write, edit, and shell calls. Reads remain available.

`quarantined_llm_call(ref="v1", query="Summarize this")` sends the query and stored text to a
separate OpenAI request using the same `OPENAI_MODEL`. That request has no tools
and no main conversation history. Its answer gets the combined labels of the
input value and the current conversation. The shared result helper hides it if
untrusted, which is the case for values produced by `read` and `shell`.
For those results, the main model sees only the new reference until inspection.

```text
read(path="original.txt")                              -> {"ref":"v1"}
quarantined_llm_call(ref="v1", query="Summarize this")  -> {"ref":"v2"}
write(path="summary.txt", content={"ref":"v2"})       -> Written.
inspect(ref="v2")                                     -> the summary text
```

The helper returns plain text. It can produce a bad summary or follow injected
instructions, so processing untrusted data does not make its output trusted.
OpenAI is allowed to receive private data under the default policy. Private text
is sent there when the helper processes it or the main model inspects it.

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
confidentiality to private while preserving its integrity. Shell output is also
labeled private/untrusted and hidden because commands can read arbitrary files.
Acknowledgments and errors cannot lower an existing conversation label.

Before a tool runs, `check_tool_policy` checks every argument against
`TOOL_POLICIES`. Literal arguments inherit the conversation label. Reference
arguments combine that label with the stored value's label. A trusted
conversation cannot pass an untrusted reference into an argument that requires
trusted input.

| Destination | May receive private data? | May receive untrusted data? |
| --- | --- | --- |
| `shell.command` | No | No |
| `read.path` | Yes | Yes |
| `write.path`, `edit.path` | Yes | No |
| `write.content`, `edit.old`, `edit.new` | Yes | Yes |
| `inspect.ref`, `quarantined_llm_call.ref`, `quarantined_llm_call.query` | Yes | Yes |
| OpenAI requests | Yes, by default | Yes |

`read` is allowed in an untrusted conversation, including when its path comes
from an untrusted reference. This lets the agent inspect a directory listing,
read a file it found, and explain its contents. Reading does not restore trust:
the contents stay private/untrusted and are hidden until inspected.

All local files and the local terminal are treated as destinations allowed to
receive private data. There is no public-file classification in this prototype.
Reads still label all file contents private/untrusted. Fixed acknowledgments
retain trusted integrity; their confidentiality includes the conversation and
any referenced arguments.

Both OpenAI call sites check `MODEL_CLEARANCE` before sending data. It defaults
to private/untrusted. Changing it to public/untrusted rejects private helper
requests and stops the main loop before private history is sent.

With `--debug`, these sequences show the rules in action. Start a fresh process
for each one, because labels persist for the whole conversation:

```text
read -> quarantined_llm_call -> write  allowed: hidden text can be saved
shell -> inspect -> read -> inspect    allowed: reading can continue after inspection
read -> inspect -> write               blocked: the conversation is untrusted
read -> shell                         blocked: the conversation is private
shell -> write                        allowed: shell output stayed hidden
shell -> shell                        blocked: the conversation is private
write(path={"ref":"v1"}, ...)          blocked if v1 is untrusted
```

Blocked calls produce a dim red `Blocked by IFC: ...` message and do not execute.
For example, after reading a file, a shell call returns
`Blocked by IFC: shell.command cannot receive private data.`

An executed shell call returns a reference and makes the conversation
private/trusted. File calls can still run, but later shell calls remain blocked
because `shell.command` only accepts public data. Inspecting the output makes
the conversation private/untrusted: reads remain allowed, while write and edit
calls are blocked.

An initially allowed command still has ordinary host access: it can read files, execute
scripts, and make network requests within that one call. These checks govern
tool invocations; they do not sandbox the process or label OS operations.

User messages are assumed public/trusted, and the Python runtime and policy
tables are trusted. There is no operation that resets or lowers a conversation
label. Restarting the CLI starts a new conversation.
