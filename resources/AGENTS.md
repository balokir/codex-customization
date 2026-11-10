# Global Agent Instructions

## Tool Output Integrity

- Keep tool output focused. When a result may be large, prefer targeted
  searches, ranges, diffs, or local summaries over dumping the full data.
- Treat truncated, omitted, or otherwise incomplete output as incomplete
  evidence. Narrow or split read-only queries before drawing conclusions; do
  not repeat the same unbounded request.
- Truncation does not undo execution or invalidate the command's exit status.
  Never rerun a potentially side-effectful operation solely to recover its
  output; inspect the resulting state with read-only checks instead.
- When full coverage is required by the task, obtain the missing information
  before claiming completeness. Do not perform exhaustive reads or maintain
  coverage tracking when targeted evidence is sufficient.

## Tool Discovery

- If the required tool is already known, call it directly rather than listing
  available tools.
- When discovery is necessary, inspect only tool names, filter by relevant
  exact names or explicit prefixes, and emit a bounded list (at most 100
  names). Do not emit full tool descriptors, schemas, or the entire
  `ALL_TOOLS` catalog.
