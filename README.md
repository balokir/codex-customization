# Codex Customization

A deliberately simple, best-effort attempt to reduce avoidable context
pollution in Codex agent sessions.

Here, context pollution means oversized, incomplete, or irrelevant tool output
that consumes context and weakens subsequent reasoning. This project targets
two specific sources:

1. **Truncated reads and tool results.** Detect when Codex receives an
   incomplete result and require a smaller, producer-bounded retry instead of
   treating partial evidence as complete.
2. **`ALL_TOOLS` exposure.** Prevent discovery code from dumping complete tool
   descriptors, schemas, and metadata when only a bounded list of tool names
   is needed.

The implementation combines semantic instructions from
[`resources/AGENTS.md`](resources/AGENTS.md) with user-level `PreToolUse` and
`PostToolUse` hooks. These are heuristic guardrails, not a security sandbox.
In particular, `PostToolUse` cannot remove output or undo side effects that
occurred before the hook received the result.

See [`DESIGN.md`](DESIGN.md) for the current architecture, supported tool
shapes, and failure model.

## Requirements

- Windows with permission to create symbolic links, such as Developer Mode.
- A user-managed Node.js installation outside the IDE or ACP distribution.
- Codex CLI for reviewing and approving hook definitions.
- A Codex host with hooks support.

## Install

Run the installer with the Node.js executable that should execute the hooks:

```powershell
node .\hooks\setup.mjs install
node .\hooks\setup.mjs status
```

The installer creates four links under `CODEX_HOME`, or `~/.codex` when
`CODEX_HOME` is unset:

- `hooks.json` points to `hooks/hooks.json` in this checkout.
- `AGENTS.md` points to `resources/AGENTS.md` in this checkout.
- `codex-customization-hooks` points to the versioned `hooks/` directory.
- `codex-customization-node.exe` points to the selected Node.js executable.

Existing destinations are never overwritten. Repeating installation is safe.
If the checkout or Node.js installation moves, uninstall using the old paths
before installing again.

Hook approval must be completed in Codex CLI; IDEA ACP does not support the
approval flow. Start Codex CLI with the same `CODEX_HOME`, open `/hooks`, verify
both definitions, and approve them when prompted. Then close the CLI session
and create a fresh IDEA Custom ACP chat.

## Current behavior

`PreToolUse`:

- checks structured MCP reads of known high-volume targets for explicit
  producer-side bounds;
- checks supported `functions.exec` source that uses `ALL_TOOLS` and denies
  direct descriptor exposure, metadata inspection, or unbounded discovery;
- returns short guidance instead of denying calls it cannot classify safely.

Shell output volume is evaluated from the completed result by `PostToolUse`.

`PostToolUse`:

- inspects recognized output fields and explicit output-truncation flags;
- recognizes the canonical Codex truncation warning and generated
  `N lines/chars truncated` markers;
- returns a blocking decision asking the agent to retry with producer-bounded
  output.

Because `PostToolUse` runs after the tool, it cannot undo completed side
effects or guarantee that a host hides output already displayed.

## Verify

Run the dependency-free automated suite:

```powershell
node .\hooks\tests\run-tests.mjs
```

After behavior changes, also use a fresh host session to verify that:

- a small command such as `Write-Output 'ok'` succeeds unchanged;
- a deliberately large result produces a block and a bounded retry;
- Codex CLI `/hooks` shows both definitions as approved;
- a fresh IDEA Custom ACP chat observes the approved hooks.

Fixture coverage does not prove that every host emits lifecycle events for
every tool type.

## Known false positive

`PostToolUse` recognizes marker text, not its provenance. Reading source code,
documentation, test fixtures, or a diff that contains a literal truncation
marker can therefore be blocked even when the result is complete.

When inspecting such content, transform or escape the marker before returning
it in tool output. For example, replace the identifying word with a neutral
placeholder in the displayed result. Reducing the range alone does not help if
the selected range still contains the marker.

This limitation is intentional in the current heuristic design and is covered
in more detail in [`DESIGN.md`](DESIGN.md#known-limitations).

## Uninstall

```powershell
node .\hooks\setup.mjs uninstall
```

Only the four owned links are removed. User settings, trust records,
repository files, and other Codex data are left untouched. Start a fresh
session to verify deactivation.

## Global instructions

[`resources/AGENTS.md`](resources/AGENTS.md) contains the semantic fallback
rules that hooks cannot fully enforce. The installer links it to
`CODEX_HOME/AGENTS.md`. An existing file or link at that destination is treated
as a conflict and is never overwritten.

## Development

For routine changes: edit, run the automated suite, and smoke-test behavior
changes in a fresh host session. Keep machine-specific diagnostics and
one-off experiments outside the public source tree.
