import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HOOK = fileURLToPath(new URL("../post_tool_use.mjs", import.meta.url));
const warning = "Warning: truncated output (original token count: 15843)\nTotal output lines: 6001\nrow 05999";
const linesMarker = "…8022 lines truncated…";
const charsMarker = "…33490 chars truncated…";
const base = {
  hook_event_name: "PostToolUse",
  tool_name: "Bash",
  tool_input: { command: "Get-Content -Raw notes.txt" },
  tool_response: "ordinary complete output",
};
let cases = 0;
function invoke(input) {
  const result = spawnSync(process.execPath, [HOOK], {
    input: typeof input === "string" ? input : JSON.stringify(input),
    encoding: "utf8", windowsHide: true,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return result.stdout;
}
function allow(label, payload) {
  assert.equal(invoke(payload), "", label);
  cases += 1;
}
function block(label, payload) {
  const stdout = invoke(payload);
  const output = JSON.parse(stdout);
  assert.deepEqual(Object.keys(output), ["decision", "reason"], label);
  assert.equal(output.decision, "block", label);
  assert.match(output.reason, /truncated.*incomplete/u, label);
  assert.equal(stdout.includes("notes.txt"), false, label);
  cases += 1;
}
allow("ordinary Bash output", base);
block("Bash warning", { ...base, tool_response: warning });
block("Bash warning after metadata", { ...base, tool_response: "Wall time: 1s\nOutput:\n" + warning });
block("CRLF warning", { ...base, tool_response: warning.replaceAll("\n", "\r\n") });
block("other command name", { ...base, tool_name: "exec_command", tool_response: warning });
block("functions.exec text result", { ...base, tool_name: "functions.exec", tool_response: warning });
block("structured MCP content", {
  ...base, tool_name: "mcp__example__read_file",
  tool_response: { content: [{ type: "text", text: warning }], isError: false },
});
block("structured MCP result nesting", {
  ...base, tool_name: "mcp__example__read_file",
  tool_response: { result: { content: [{ type: "text", text: warning }] } },
});
block("IDEA lines-truncated marker", {
  ...base, tool_name: "mcp__idea__execute_tool",
  tool_response: {
    content: [{ type: "text", text: `L1000: before\n${linesMarker}\nL9023: after` }],
    isError: false,
  },
});
block("nested chars-truncated marker", {
  ...base, tool_name: "mcp__idea__execute_tool",
  tool_response: {
    result: {
      content: [{
        type: "text",
        text: JSON.stringify({ content: `before ${charsMarker} after` }),
      }],
    },
  },
});
block("ASCII lines-truncated marker", {
  ...base, tool_response: "...8022 lines truncated...",
});
block("ASCII chars-truncated marker", {
  ...base, tool_response: "...33490 chars truncated...",
});
block("object stdout", { ...base, tool_response: { stdout: warning } });
block("object output", { ...base, tool_response: { output: warning } });
block("array of content blocks", { ...base, tool_response: [{ type: "text", text: warning }] });
block("structured output-truncated flag", { ...base, tool_response: { output_truncated: true, output: "short" } });
block("structured is-output-truncated flag", { ...base, tool_response: { result: { is_output_truncated: true } } });
block("structured camelCase flag", { ...base, tool_response: { isOutputTruncated: true } });
allow("normal MCP content", { ...base, tool_response: { content: [{ type: "text", text: "complete" }] } });
allow("normal functions.exec response", { ...base, tool_name: "functions.exec", tool_response: { output: "complete" } });
allow("generic truncated field is application data", { ...base, tool_response: { truncated: true, content: "complete" } });
allow("unrelated domain text is not tool output", { ...base, tool_response: { description: warning } });
allow("generated marker in unrelated domain data", {
  ...base, tool_response: { description: charsMarker, content: "complete" },
});
allow("marker only in tool_input", { ...base, tool_input: { command: warning }, tool_response: "complete" });
allow("marker only in unrelated metadata", { ...base, private_note: warning });
allow("normal phrase", { ...base, tool_response: "output was truncated earlier" });
allow("warning not standalone", { ...base, tool_response: "log: " + warning });
allow("warning in quoted source", { ...base, tool_response: "const x = 'Warning: truncated output (original token count: 15843)';" });
allow("missing token count", { ...base, tool_response: "Warning: truncated output" });
allow("generated marker without ellipses", { ...base, tool_response: "33490 chars truncated" });
allow("generated marker without count", { ...base, tool_response: "…chars truncated…" });
allow("wrong event", { ...base, hook_event_name: "PreToolUse", tool_response: warning });
allow("no response", { ...base, tool_response: undefined });
allow("null response", { ...base, tool_response: null });
allow("malformed input", "{not-json");
allow("oversized input", "x".repeat(1024 * 1024 + 1));
allow("empty input", "");
console.log("PostToolUse output completeness: " + cases + " fixtures passed");
