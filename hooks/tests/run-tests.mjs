import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  lstatSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ENGINE_URL = new URL("../pre_tool_use.mjs", import.meta.url);
const ENGINE_PATH = fileURLToPath(ENGINE_URL);
const POLICY_PATH = fileURLToPath(new URL("../policy.json", import.meta.url));
const CONFIG_PATH = fileURLToPath(new URL("../hooks.json", import.meta.url));
const AGENTS_PATH = fileURLToPath(
  new URL("../../resources/AGENTS.md", import.meta.url),
);
const EXPECTED_ENGINE_SHA256 =
  "8f4c6eb2b877ca610b776a082757c412ba6930e2292608c91c266e593b19bd4c";
const EXPECTED_POLICY_SHA256 =
  "5959c76e353c0be962ebe60e0efc5ccffaba98509794220afdff651544aef046";
const EXPECTED_TIMEOUT_SECONDS = 5;
const SECRET_PAYLOAD = "E1_SECRET_PAYLOAD_7391";
const SECRET_METADATA = "E1_SECRET_METADATA_1842";

function invoke(input) {
  const result = spawnSync(process.execPath, [ENGINE_PATH], {
    input: typeof input === "string" ? input : JSON.stringify(input),
    encoding: "utf8",
    windowsHide: true,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  return result.stdout;
}

function assertEmpty(name, input) {
  assert.equal(invoke(input), "", `${name} should produce empty output`);
}

function assertGuidance(name, input) {
  const stdout = invoke(input);
  assert.notEqual(stdout, "", `${name} should produce guidance`);

  const output = JSON.parse(stdout);
  assert.deepEqual(Object.keys(output), ["hookSpecificOutput"]);
  assert.deepEqual(Object.keys(output.hookSpecificOutput), [
    "hookEventName",
    "additionalContext",
  ]);
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(typeof output.hookSpecificOutput.additionalContext, "string");
  assert.ok(output.hookSpecificOutput.additionalContext.length > 0);
  assert.ok(output.hookSpecificOutput.additionalContext.length <= 240);
  assert.equal("permissionDecision" in output.hookSpecificOutput, false);
  assert.equal(stdout.includes(SECRET_PAYLOAD), false);
  assert.equal(stdout.includes(SECRET_METADATA), false);
}

function assertDeny(name, input) {
  const stdout = invoke(input);
  assert.notEqual(stdout, "", `${name} should produce a deny decision`);

  const output = JSON.parse(stdout);
  assert.deepEqual(Object.keys(output), ["hookSpecificOutput"]);
  assert.deepEqual(Object.keys(output.hookSpecificOutput), [
    "hookEventName",
    "permissionDecision",
    "permissionDecisionReason",
  ]);
  assert.equal(output.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(output.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(typeof output.hookSpecificOutput.permissionDecisionReason, "string");
  assert.ok(output.hookSpecificOutput.permissionDecisionReason.length > 0);
  assert.ok(output.hookSpecificOutput.permissionDecisionReason.length <= 240);
  assert.equal(stdout.includes(SECRET_PAYLOAD), false);
  assert.equal(stdout.includes(SECRET_METADATA), false);
}

const safeEnvelope = {
  session_id: "fixture-session",
  transcript_path: null,
  cwd: "C:\\fixture",
  hook_event_name: "PreToolUse",
  model: "fixture-model",
  permission_mode: "default",
  turn_id: "fixture-turn",
  tool_name: "Bash",
  tool_use_id: "fixture-tool-use",
  tool_input: { command: "Write-Output 'bounded fixture'" },
};

assertEmpty("recognized safe documented envelope", safeEnvelope);
assertEmpty("irrelevant event", {
  ...safeEnvelope,
  hook_event_name: "PostToolUse",
});
assertEmpty("supported code freeform shape", {
  ...safeEnvelope,
  tool_name: "functions.exec",
  tool_input: "text('bounded fixture')",
});
assertEmpty("supported code object shape", {
  ...safeEnvelope,
  tool_name: "functions.exec",
  tool_input: { code: "text('bounded fixture')" },
});
assertEmpty("supported structured shape", {
  ...safeEnvelope,
  tool_name: "mcp__fixture__read_file",
  tool_input: { path: "fixture.txt", offset: 0, limit: 10 },
});

assertGuidance("unknown tool", {
  ...safeEnvelope,
  tool_name: "UnknownFixtureTool",
  tool_input: { payload: SECRET_PAYLOAD },
  private_metadata: SECRET_METADATA,
});
assertGuidance("missing event", {
  tool_name: "Bash",
  tool_input: { command: SECRET_PAYLOAD },
  private_metadata: SECRET_METADATA,
});
assertGuidance("missing tool name", {
  ...safeEnvelope,
  tool_name: undefined,
  tool_input: { command: SECRET_PAYLOAD },
  private_metadata: SECRET_METADATA,
});
assertGuidance("missing tool input", {
  ...safeEnvelope,
  tool_input: undefined,
  private_metadata: SECRET_METADATA,
});
assertGuidance("malformed JSON", `{not-json:${SECRET_PAYLOAD}:${SECRET_METADATA}`);
assertGuidance("newer unsupported schema", {
  ...safeEnvelope,
  schema_version: 2,
  tool_input: { command: SECRET_PAYLOAD },
  private_metadata: SECRET_METADATA,
});
assertGuidance("invalid supported tool input", {
  ...safeEnvelope,
  tool_input: { command: { payload: SECRET_PAYLOAD } },
  private_metadata: SECRET_METADATA,
});
assertGuidance("oversized envelope", "x".repeat(65537) + SECRET_PAYLOAD + SECRET_METADATA);

// Shell read/search volume is checked from actual output by PostToolUse.
// PreToolUse must not reject calls on guessed file size or operation count.
assertEmpty("shell file size probe", {
  ...safeEnvelope,
  tool_input: { command: "Get-Item -LiteralPath 'server.log' | Select-Object Length" },
});
assertEmpty("read AGENTS.md without a special-case deny", {
  ...safeEnvelope,
  tool_input: { command: "Get-Content -Raw -LiteralPath 'AGENTS.md'" },
});
assertEmpty("read log without preemptive filename deny", {
  ...safeEnvelope,
  tool_input: { command: "Get-Content -Raw 'server.log'" },
});
assertEmpty("multiple shell reads without blanket deny", {
  ...safeEnvelope,
  tool_input: { command: "Get-Content first.txt; Get-Content second.txt" },
});
assertEmpty("broad rg search without blanket deny", {
  ...safeEnvelope,
  tool_input: { command: "rg -n 'test' ." },
});
assertEmpty("dynamic shell target", {
  ...safeEnvelope,
  tool_input: { command: "Get-Content -LiteralPath $fixturePath" },
});
assertEmpty("max_output_tokens is not a PreToolUse shell rule", {
  ...safeEnvelope,
  tool_input: { command: "Get-Content -Raw 'AGENTS.md'", max_output_tokens: 10 },
});
assertEmpty("bounded shell read", {
  ...safeEnvelope,
  tool_input: { command: "Get-Content -LiteralPath 'server.log' -TotalCount 30" },
});
assertEmpty("structured bounded read", {
  ...safeEnvelope,
  tool_name: "mcp__fixture__read_file",
  tool_input: { path: "C:\\fixtures\\build.log", offset: 20, limit: 20 },
});
assertEmpty("unrelated structured tool", {
  ...safeEnvelope,
  tool_name: "mcp__fixture__write_file",
  tool_input: { path: "C:\\fixtures\\build.log", content: "bounded fixture" },
});

assertGuidance("structured read missing path", {
  ...safeEnvelope,
  tool_name: "mcp__fixture__read_file",
  tool_input: { offset: 0, secret: SECRET_PAYLOAD },
  private_metadata: SECRET_METADATA,
});
assertGuidance("structured dynamic path", {
  ...safeEnvelope,
  tool_name: "mcp__fixture__read_file",
  tool_input: { path: `C:\\fixtures\\${SECRET_PAYLOAD}\\*.log` },
  private_metadata: SECRET_METADATA,
});
assertDeny("structured multiple reads", {
  ...safeEnvelope,
  tool_name: "mcp__fixture__read_file",
  tool_input: { path: ["first.txt", "second.txt"], secret: SECRET_PAYLOAD },
  private_metadata: SECRET_METADATA,
});
assertEmpty("read tokens inside quoted output are not commands", {
  ...safeEnvelope,
  tool_input: {
    command: "Write-Output \"Get-Content AGENTS.md; rg -n secret .\"",
  },
});

function codeEnvelope(source) {
  return {
    ...safeEnvelope,
    tool_name: "functions.exec",
    tool_input: { code: source },
    private_metadata: SECRET_METADATA,
  };
}

assertEmpty("exact-name availability check", codeEnvelope(`
  const available = ALL_TOOLS.some(
    x => x.name === "mcp__fixture__read_file"
  );
  text({ available });
`));
assertEmpty("exact-name names-only discovery at limit 100", codeEnvelope(`
  const names = ALL_TOOLS
    .map(x => x.name)
    .filter(name => name === "mcp__fixture__read_file");
  text({ count: names.length, names: names.slice(0, 100) });
`));
assertEmpty("explicit-prefix names-only discovery at limit 100", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__") || name.startsWith("mcp__safe__"));
  text({ count: names.length, names: names.slice(0, 100) });
`));
assertEmpty("explicit-prefix names-only discovery at limit zero", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"));
  text({ count: names.length, names: names.slice(0, 0) });
`));
assertEmpty("pipeline-bounded names-only discovery", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"))
    .slice(0, 100);
  text({ count: names.length, names });
`));

assertDeny("direct ALL_TOOLS serialization", codeEnvelope(`
  text(JSON.stringify(ALL_TOOLS)); // ${SECRET_PAYLOAD}
`));
assertDeny("direct ALL_TOOLS emission", codeEnvelope(`
  text(ALL_TOOLS); // ${SECRET_PAYLOAD}
`));
assertDeny("descriptor description filtering", codeEnvelope(`
  const matches = ALL_TOOLS.filter(item => item.description.includes("fixture"));
  text(matches); // ${SECRET_PAYLOAD}
`));
assertDeny("descriptor schema mapping", codeEnvelope(`
  const schemas = ALL_TOOLS.map(item => item.inputSchema);
  text(schemas); // ${SECRET_PAYLOAD}
`));
assertDeny("complete descriptor mapping", codeEnvelope(`
  const descriptors = ALL_TOOLS.map(item => item);
  text(descriptors); // ${SECRET_PAYLOAD}
`));
assertDeny("unrestricted names inventory without filter", codeEnvelope(`
  const names = ALL_TOOLS.map(item => item.name);
  text({ count: names.length, names: names.slice(0, 100) });
`));
assertDeny("filtered names inventory without output limit", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"));
  text({ count: names.length, names });
`));
assertDeny("names output limit 101", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"));
  text({ count: names.length, names: names.slice(0, 101) });
`));
assertDeny("generic descriptor search term", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.includes("tool"));
  text({ count: names.length, names: names.slice(0, 100) });
`));
assertDeny("generic exact discovery term", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name === "memory");
  text({ count: names.length, names: names.slice(0, 100) });
`));
assertDeny("descriptor filtering before name reduction", codeEnvelope(`
  const names = ALL_TOOLS
    .filter(item => item.name.startsWith("mcp__fixture__"))
    .map(item => item.name)
    .slice(0, 100);
  text({ count: names.length, names });
`));
assertDeny("descriptor find before name reduction", codeEnvelope(`
  const descriptor = ALL_TOOLS.find(
    item => item.name === "mcp__fixture__read_file"
  );
  text(descriptor); // ${SECRET_PAYLOAD}
`));
assertDeny("descriptor findIndex before name reduction", codeEnvelope(`
  const descriptorIndex = ALL_TOOLS.findIndex(
    item => item.name === "mcp__fixture__read_file"
  );
  text({ descriptorIndex }); // ${SECRET_PAYLOAD}
`));
assertDeny("summary with an extra metadata field", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"));
  text({ count: names.length, names: names.slice(0, 100), metadata: ${JSON.stringify(SECRET_PAYLOAD)} });
`));
assertDeny("names summary plus second output sink", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"));
  text({ count: names.length, names: names.slice(0, 100) });
  console.log(${JSON.stringify(SECRET_PAYLOAD)});
`));
assertDeny("unrelated filter and slice do not authorize inventory", codeEnvelope(`
  const names = ALL_TOOLS.map(item => item.name);
  const other = values
    .filter(name => name.startsWith("mcp__fixture__"))
    .slice(0, 100);
  text({ count: names.length, names }); // ${SECRET_PAYLOAD}
`));
assertDeny("unrelated slice does not bound filtered names", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith("mcp__fixture__"));
  const other = values.slice(0, 100);
  text({ count: names.length, names }); // ${SECRET_PAYLOAD}
`));

assertGuidance("dynamic explicit-prefix value", codeEnvelope(`
  const prefix = "mcp__fixture__";
  const names = ALL_TOOLS
    .map(item => item.name)
    .filter(name => name.startsWith(prefix));
  text({ count: names.length, names: names.slice(0, 100) });
  // ${SECRET_PAYLOAD}
`));
assertGuidance("computed name-field access", codeEnvelope(`
  const names = ALL_TOOLS
    .map(item => item["name"])
    .filter(name => name.startsWith("mcp__fixture__"));
  text({ count: names.length, names: names.slice(0, 100) });
  // ${SECRET_PAYLOAD}
`));
assertGuidance("obfuscated ALL_TOOLS global reference", codeEnvelope(`
  const catalog = globalThis["ALL_" + "TOOLS"];
  text(catalog); // ${SECRET_PAYLOAD}
`));
assertGuidance("aliased ALL_TOOLS source", codeEnvelope(`
  const catalog = ALL_TOOLS;
  text(catalog); // ${SECRET_PAYLOAD}
`));
assertGuidance("computed descriptor metadata access", codeEnvelope(`
  const descriptions = ALL_TOOLS.map(item => item["description"]);
  text(descriptions); // ${SECRET_PAYLOAD}
`));
assertGuidance("ALL_TOOLS token in regular expression source", codeEnvelope(`
  const pattern = /ALL_TOOLS/u;
  text({ matched: pattern.test("fixture") }); // ${SECRET_PAYLOAD}
`));
assertGuidance(
  "ALL_TOOLS template interpolation",
  codeEnvelope("text(`${ALL_TOOLS}`); // " + SECRET_PAYLOAD),
);

function sha256Text(text) {
  // Git may check out these UTF-8 source files using CRLF on Windows.
  // Verify canonical file content without depending on checkout line endings.
  return createHash("sha256").update(text.replace(/\r\n/gu, "\n"), "utf8").digest("hex");
}

function sha256(path) {
  return sha256Text(readFileSync(path, "utf8"));
}

assert.equal(sha256Text("a\nb\n"), sha256Text("a\r\nb\r\n"));

function pathExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function resolvedLinkTarget(path) {
  return resolve(dirname(path), readlinkSync(path));
}

const deploymentConfig = JSON.parse(readFileSync(CONFIG_PATH, "utf8"));
const matcherGroup = deploymentConfig.hooks?.PreToolUse?.[0];
const deploymentHandler = matcherGroup?.hooks?.[0];
const SETUP = fileURLToPath(new URL("../setup.mjs", import.meta.url));
const POST_TEST = fileURLToPath(new URL("./post_tool_use.test.mjs", import.meta.url));
const postGroup = deploymentConfig.hooks?.PostToolUse?.[0];
const postHandler = postGroup?.hooks?.[0];
assert.equal(postGroup?.matcher, "*");
assert.equal(postHandler?.type, "command");
assert.equal(postHandler?.timeout, EXPECTED_TIMEOUT_SECONDS);
assert.equal(postHandler?.command?.includes("codex-customization-hooks/post_tool_use.mjs"), true);
assert.equal(postHandler?.commandWindows?.includes("codex-customization-hooks\\post_tool_use.mjs"), true);
assert.equal(postHandler?.commandWindows?.includes("C:\\nvm4w"), false);
assert.equal(postHandler?.commandWindows?.includes("C:\\work"), false);


assert.deepEqual(Object.keys(deploymentConfig).sort(), ["description", "hooks"]);
assert.equal(matcherGroup.matcher, "*");
assert.equal(deploymentHandler.type, "command");
assert.equal(deploymentHandler.timeout, EXPECTED_TIMEOUT_SECONDS);
assert.equal(deploymentHandler.command.includes("codex-customization-node"), true);
assert.equal(deploymentHandler.commandWindows.includes("codex-customization-node.exe"), true);
assert.equal(deploymentHandler.commandWindows.includes("Join-Path"), true);
assert.equal(deploymentHandler.commandWindows.includes("C:\\nvm4w"), false);
assert.equal(deploymentHandler.commandWindows.includes("C:\\work"), false);
assert.equal(sha256(ENGINE_PATH), EXPECTED_ENGINE_SHA256);
assert.equal(sha256(POLICY_PATH), EXPECTED_POLICY_SHA256);

const fixtureRoot = mkdtempSync(join(tmpdir(), "codex hooks portability "));
const nodeName = process.platform === "win32"
  ? "codex-customization-node.exe"
  : "codex-customization-node";
const links = [
  join(fixtureRoot, "hooks.json"),
  join(fixtureRoot, "AGENTS.md"),
  join(fixtureRoot, "codex-customization-hooks"),
  join(fixtureRoot, nodeName),
];

function setup(action) {
  return spawnSync(process.execPath, [SETUP, action], {
    env: { ...process.env, CODEX_HOME: fixtureRoot },
    encoding: "utf8",
    windowsHide: true,
  });
}
function assertSetup(action) {
  const result = setup(action);
  assert.equal(result.status, 0, result.stderr);
}

try {
  // A user-owned destination stops installation without modifying other paths.
  writeFileSync(links[0], "user-config", "utf8");
  assert.notEqual(setup("install").status, 0);
  assert.equal(readFileSync(links[0], "utf8"), "user-config");
  assert.equal(pathExists(links[1]), false);
  rmSync(links[0]);

  // A user-owned AGENTS.md is preserved and blocks the transaction.
  writeFileSync(links[1], "user-instructions", "utf8");
  assert.notEqual(setup("install").status, 0);
  assert.equal(readFileSync(links[1], "utf8"), "user-instructions");
  assert.equal(pathExists(links[0]), false);
  assert.equal(pathExists(links[2]), false);
  assert.equal(pathExists(links[3]), false);
  rmSync(links[1]);

  assertSetup("install");
  assertSetup("install");
  const installedStatus = setup("status");
  assert.equal(installedStatus.status, 0, installedStatus.stderr);
  assert.match(installedStatus.stdout, /^AGENTS\.md: linked$/mu);
  for (const link of links) assert.equal(lstatSync(link).isSymbolicLink(), true);
  assert.equal(realpathSync(links[0]), realpathSync(CONFIG_PATH));
  assert.equal(realpathSync(links[1]), realpathSync(AGENTS_PATH));
  assert.equal(realpathSync(links[2]), realpathSync(dirname(ENGINE_PATH)));
  assert.equal(realpathSync(links[3]), realpathSync(process.execPath));

  const safe = { ...safeEnvelope, tool_input: { command: "Write-Output 'ok'" } };
  const formerlyDenied = {
    ...safeEnvelope,
    tool_input: { command: "Get-Content -Raw -LiteralPath 'AGENTS.md'" },
  };
  const shell = process.platform === "win32" ? "pwsh.exe" : "sh";
  const args = process.platform === "win32"
    ? ["-NoProfile", "-NonInteractive", "-Command", deploymentHandler.commandWindows]
    : ["-c", deploymentHandler.command];

  function hook(input) {
    return spawnSync(shell, args, {
      input: JSON.stringify(input),
      env: { ...process.env, CODEX_HOME: fixtureRoot },
      encoding: "utf8",
      windowsHide: true,
    });
  }
  const allowed = hook(safe);
  assert.equal(allowed.status, 0, allowed.stderr);
  assert.equal(allowed.stdout, "");
  const readAllowed = hook(formerlyDenied);
  assert.equal(readAllowed.status, 0, readAllowed.stderr);
  assert.equal(readAllowed.stdout, "");
  const postArgs = process.platform === "win32"
    ? ["-NoProfile", "-NonInteractive", "-Command", postHandler.commandWindows]
    : ["-c", postHandler.command];
  function postHook(response) {
    return spawnSync(shell, postArgs, {
      input: JSON.stringify({
        ...safeEnvelope, hook_event_name: "PostToolUse",
        tool_response: response,
      }),
      env: { ...process.env, CODEX_HOME: fixtureRoot },
      encoding: "utf8", windowsHide: true,
    });
  }
  const postAllowed = postHook("normal complete output");
  assert.equal(postAllowed.status, 0, postAllowed.stderr);
  assert.equal(postAllowed.stdout, "");
  const postBlocked = postHook("Warning: truncated output (original token count: 15843)\nTotal output lines: 6001\n");
  assert.equal(postBlocked.status, 0, postBlocked.stderr);
  assert.equal(JSON.parse(postBlocked.stdout).decision, "block");
  const postObjectBlocked = postHook({
    content: [{ type: "text", text: "Warning: truncated output (original token count: 15843)\nTotal output lines: 6001" }],
  });
  assert.equal(postObjectBlocked.status, 0, postObjectBlocked.stderr);
  assert.equal(JSON.parse(postObjectBlocked.stdout).decision, "block");
  const postIdeaMarkerBlocked = postHook({
    content: [{ type: "text", text: "L1000: before\n…8022 lines truncated…\nL9023: after" }],
    isError: false,
  });
  assert.equal(postIdeaMarkerBlocked.status, 0, postIdeaMarkerBlocked.stderr);
  assert.equal(JSON.parse(postIdeaMarkerBlocked.stdout).decision, "block");
  const postCharsMarkerBlocked = postHook({
    result: { content: [{ type: "text", text: "before …33490 chars truncated… after" }] },
  });
  assert.equal(postCharsMarkerBlocked.status, 0, postCharsMarkerBlocked.stderr);
  assert.equal(JSON.parse(postCharsMarkerBlocked.stdout).decision, "block");


  assertSetup("uninstall");
  assertSetup("uninstall");
  for (const link of links) assert.equal(pathExists(link), false);

  // Uninstall must refuse an unexpected file rather than removing it.
  writeFileSync(links[0], "preserve", "utf8");
  assert.notEqual(setup("uninstall").status, 0);
  assert.equal(readFileSync(links[0], "utf8"), "preserve");
} finally {
  rmSync(fixtureRoot, { recursive: true, force: true });
}

const postSuite = spawnSync(process.execPath, [POST_TEST], {
  encoding: "utf8", windowsHide: true,
});
assert.equal(postSuite.status, 0, postSuite.stderr);
process.stdout.write(postSuite.stdout);

console.log("E1/E2/E3: fixture cases passed; portable hooks install and smoke tests passed");
