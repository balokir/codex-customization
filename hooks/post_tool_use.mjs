// Observe completed tool results, not the commands that produced them.
// Only explicit truncation markers/metadata cause a block.
// The host decides which tool types actually emit PostToolUse events.
const MAX_INPUT_BYTES = 1024 * 1024;
const TRUNCATION_MARKERS = [
  /(?:^|\r?\n)[ \t]*Warning: truncated output \(original token count: [0-9]+\)(?:\r?\n|$)/u,
  /(?:…|\.\.\.)[ \t]*[0-9]+[ \t]+(?:lines|chars)[ \t]+truncated[ \t]*(?:…|\.\.\.)/iu,
];
const REASON = "Tool output was truncated and is incomplete. Retry with smaller, explicitly bounded output; do not treat the previous result as complete.";
const OUTPUT_FIELDS = [
  "output", "stdout", "stderr", "aggregated_output",
  "text", "content", "result", "response",
];
const MAX_NESTING_DEPTH = 8;

function hasTruncationEvidence(root) {
  const pending = [{ value: root, depth: 0 }];
  while (pending.length > 0) {
    const { value, depth } = pending.pop();
    if (typeof value === "string") {
      if (TRUNCATION_MARKERS.some((pattern) => pattern.test(value))) return true;
      continue;
    }
    if (value === null || typeof value !== "object" || depth >= MAX_NESTING_DEPTH) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) pending.push({ value: item, depth: depth + 1 });
      continue;
    }
    // Generic 'truncated' may belong to application data, so do not infer
    // an incomplete tool result from it. Inspect only output-specific flags.
    if (value.output_truncated === true || value.is_output_truncated === true
        || value.isOutputTruncated === true) {
      return true;
    }
    // Restrict traversal to recognized output-bearing fields so request
    // metadata, source snippets, and arbitrary domain fields are not scanned.
    for (const key of OUTPUT_FIELDS) {
      if (Object.hasOwn(value, key)) {
        pending.push({ value: value[key], depth: depth + 1 });
      }
    }
  }
  return false;
}

async function readBounded() {
  let bytes = 0;
  const chunks = [];
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > MAX_INPUT_BYTES) return null;
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const raw = await readBounded();
if (raw !== null) {
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    // Invalid JSON must not cause unrelated tool results to fail.
  }
  if (event?.hook_event_name === "PostToolUse"
      && hasTruncationEvidence(event.tool_response)) {
    process.stdout.write(JSON.stringify({ decision: "block", reason: REASON }) + "\n");
  }
}
