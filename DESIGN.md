# Design

This document describes the current implementation of the Codex customization
hooks. It is descriptive rather than a roadmap: the source and tests remain
authoritative when behavior changes.

## Scope

The project supplies user-level guardrails for two recurring failure modes:

1. reading or returning more tool output than the model receives completely;
2. exposing complete `ALL_TOOLS` descriptors during dynamic tool discovery.

The hooks complement the semantic rules installed from `resources/AGENTS.md`.
They do not parse arbitrary shell programs, provide a security boundary, or
guarantee lifecycle coverage in every Codex host.

## Components

| Component | Responsibility |
| --- | --- |
| `resources/AGENTS.md` | Semantic fallback rules installed at user scope. |
| `hooks/hooks.json` | User-level `PreToolUse` and `PostToolUse` definitions. |
| `hooks/policy.json` | Versioned limits, supported tool shapes, guidance, and denial reasons. |
| `hooks/pre_tool_use.mjs` | Pre-execution structured-read and tool-discovery classification. |
| `hooks/post_tool_use.mjs` | Post-execution detection of incomplete tool results. |
| `hooks/setup.mjs` | Ownership-safe installation, status, and removal of four links. |
| `hooks/tests/` | Dependency-free fixture, installation, and smoke tests. |

The runtime has no package dependencies. Hook scripts use only Node.js built-in
modules.

## Deployment model

The repository remains the source of truth. Installation creates stable links
inside `CODEX_HOME` rather than copying versioned files:

```text
CODEX_HOME/
├── hooks.json                    -> <checkout>/hooks/hooks.json
├── AGENTS.md                     -> <checkout>/resources/AGENTS.md
├── codex-customization-hooks     -> <checkout>/hooks
└── codex-customization-node.exe  -> <selected Node.js executable>
```

`hooks.json` invokes the stable links, so it contains no checkout-specific or
Node-installation-specific path. The installer refuses to overwrite existing
destinations and removes only links whose targets it owns.

Codex hook trust is managed by the host. Approval is available in Codex CLI,
not IDEA ACP. Installation and changes therefore require opening `/hooks` in a
Codex CLI session that uses the same `CODEX_HOME`, approving both definitions,
and then starting a fresh IDEA Custom ACP chat.

## Event flow

For a tool call, the host may invoke these independent lifecycle stages:

```text
tool request
    |
    v
PreToolUse -- deny --> tool does not run
    |
    +-- guidance --> tool remains allowed with model-visible context
    |
    v
tool execution
    |
    v
PostToolUse -- block --> completed result is rejected and should be retried
    |
    +-- no output --> completed result is accepted
```

The host decides which tools emit each lifecycle event. Wildcard matching in
`hooks.json` does not create events that the host does not support.

## PreToolUse

### Input and policy

The handler loads and validates `hooks/policy.json` for every invocation. It
accepts a JSON event from standard input with a maximum size of 65,536 bytes.
The supported version is `inputSchemaVersion: 1`.

The configured tool families are:

- shell tool name `Bash`;
- code tool name `functions.exec`;
- structured MCP names matching `mcp__<server>__<tool>`.

Malformed, oversized, unsupported, or unknown inputs receive bounded guidance
and are not denied. Policy-load failure follows the same fail-open behavior.
Guidance and denial reasons are capped at 240 characters.

### Structured reads

MCP tools whose names resemble read/get/fetch operations are treated as
structured reads. The classifier recognizes path fields named `path`, `file`,
`filePath`, or `filename` and bounds expressed as:

- a positive `limit` or `length`;
- `startLine` plus `endLine`;
- a numeric `range.start` plus `range.end`.

An unbounded read is denied only when its path names a configured high-volume
file or extension. Multiple paths are denied. Dynamic paths and ambiguous
shapes receive guidance rather than a denial.

Shell reads are not classified for size before execution. Actual incomplete
shell output is handled by `PostToolUse`.

### Tool discovery

For supported code calls that reference `ALL_TOOLS`, the handler scans source
for unsafe discovery patterns. It denies cases such as:

- serializing or emitting the descriptor collection directly;
- inspecting descriptions, schemas, or complete descriptors;
- filtering descriptor objects before reducing them to names;
- returning an unrestricted inventory or more than 100 names;
- discovery using only generic terms such as `tool`, `skill`, `search`, or
  `memory`.

Known safe shapes reduce descriptors to names first, use an exact name or an
explicit prefix, cap the result at 100, and emit only a bounded summary.

This is source-pattern classification, not a JavaScript parser or security
boundary. Dynamically assembled or obfuscated source may not be classified.

## PostToolUse

The handler reads at most 1 MiB from standard input. Oversized, malformed, or
non-`PostToolUse` events produce no hook output.

For recognized events it traverses output-bearing values to a maximum nesting
depth of eight. Recognized fields include `output`, `stdout`, `stderr`,
`aggregated_output`, `text`, `content`, `result`, and `response`.

The result is blocked when the traversal finds either:

- an explicit output flag such as `output_truncated`,
  `is_output_truncated`, or `isOutputTruncated`; or
- a canonical Codex warning or generated ellipsis marker reporting a numeric
  count of truncated lines or characters.

Other event metadata and `tool_input` are deliberately ignored. Normal results
produce no output. Detection returns a small JSON blocking decision asking for
a narrower producer-bounded retry.

Post-execution blocking cannot undo file writes, external messages, process
execution, or other side effects that the tool already completed.

## Safety and privacy properties

- Hook responses contain only versioned guidance or denial text.
- Tool inputs and tool responses are not written to disk.
- No diagnostics, environment dumps, command bodies, or descriptor schemas are
  emitted by the production handlers.
- Input sizes, response sizes, traversal depth, and message lengths are
  bounded.
- Uncertain `PreToolUse` cases fail open with guidance to limit false denials.
- Installation does not overwrite unowned files or links.

These properties reduce accidental disclosure but do not make the hooks a
sandbox. A host can skip lifecycle events, and unrecognized inputs remain
governed by the installed `CODEX_HOME/AGENTS.md`.

## Known limitations

### Literal marker false positive

`PostToolUse` identifies marker syntax without knowing whether it was generated
by the host or intentionally present in the underlying content. A complete
read of documentation, source code, a fixture, or a diff containing a literal
marker can therefore be blocked.

The practical inspection workaround is to transform or escape the marker in
the displayed result. Splitting the read helps only when the selected part no
longer contains the marker. The original file does not need to be modified.

### Lifecycle timing

`PostToolUse` sees only the event supplied by the host. A marker introduced
later while a host serializes or compacts the result cannot be detected.
Conversely, output may already have been shown before a blocking decision.

### Coverage and heuristics

- `matcher: "*"` does not guarantee that every tool emits hook events.
- Structured-read recognition depends on tool names and common argument keys.
- Tool-discovery checks recognize reviewed source patterns, not all valid
  JavaScript programs.
- Inputs exceeding the configured caps are not inspected completely.
- Unfamiliar truncation formats are allowed until explicitly supported.

## Verification model

`hooks/tests/run-tests.mjs` is the public entry point. It verifies:

- policy validation and input normalization;
- structured-read allow, guidance, and denial cases;
- safe and unsafe `ALL_TOOLS` discovery shapes;
- absence of fixture payloads from hook responses;
- `PostToolUse` markers, structured response fields, flags, and negative cases;
- installation ownership, idempotence, status, uninstall, all four links, and
  preservation of an existing user-owned `AGENTS.md`.

Automated fixtures prove handler behavior for reviewed envelopes. Changes to
host integration require a fresh-session smoke test because host lifecycle
support and trust state are external to this repository.
