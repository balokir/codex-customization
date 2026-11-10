import { readFile } from "node:fs/promises";

const POLICY_URL = new URL("./policy.json", import.meta.url);
const FALLBACK_GUIDANCE =
  "Hook policy could not be loaded, so the call was not blocked. Review the versioned hook files before relying on this guardrail.";
const FALLBACK_GUIDANCE_LIMIT = 240;

function writeGuidance(message, limit = FALLBACK_GUIDANCE_LIMIT) {
  const boundedLimit = Number.isSafeInteger(limit) && limit > 0
    ? Math.min(limit, FALLBACK_GUIDANCE_LIMIT)
    : FALLBACK_GUIDANCE_LIMIT;
  const additionalContext = String(message).slice(0, boundedLimit);

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      additionalContext,
    },
  }));
}

function writeDeny(reason, limit = FALLBACK_GUIDANCE_LIMIT) {
  const boundedLimit = Number.isSafeInteger(limit) && limit > 0
    ? Math.min(limit, FALLBACK_GUIDANCE_LIMIT)
    : FALLBACK_GUIDANCE_LIMIT;
  const permissionDecisionReason = String(reason).slice(0, boundedLimit);

  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason,
    },
  }));
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validatePolicy(candidate) {
  if (!isRecord(candidate)
      || typeof candidate.engineVersion !== "string"
      || !Number.isSafeInteger(candidate.inputSchemaVersion)
      || !Number.isSafeInteger(candidate.maxInputBytes)
      || !Number.isSafeInteger(candidate.maxGuidanceChars)
      || !Number.isSafeInteger(candidate.maxDecisionReasonChars)
      || !isRecord(candidate.supportedTools)
      || !Array.isArray(candidate.supportedTools.shell)
      || !candidate.supportedTools.shell.every((name) => typeof name === "string")
      || !Array.isArray(candidate.supportedTools.code)
      || !candidate.supportedTools.code.every((name) => typeof name === "string")
      || typeof candidate.supportedTools.mcpNamePattern !== "string"
      || !isRecord(candidate.guidance)
      || !isRecord(candidate.boundedReads)
      || !Array.isArray(candidate.boundedReads.knownHighVolumeNames)
      || !candidate.boundedReads.knownHighVolumeNames.every(
        (name) => typeof name === "string",
      )
      || !Array.isArray(candidate.boundedReads.knownHighVolumeExtensions)
      || !candidate.boundedReads.knownHighVolumeExtensions.every(
        (extension) => typeof extension === "string",
      )
      || !isRecord(candidate.boundedReads.denyReasons)
      || !isRecord(candidate.toolDiscovery)
      || !Number.isSafeInteger(candidate.toolDiscovery.maxNames)
      || candidate.toolDiscovery.maxNames < 0
      || !Array.isArray(candidate.toolDiscovery.genericTerms)
      || !candidate.toolDiscovery.genericTerms.every(
        (term) => typeof term === "string",
      )
      || !isRecord(candidate.toolDiscovery.denyReasons)) {
    throw new Error("Invalid policy");
  }

  for (const key of [
    "malformedJson",
    "oversizedInput",
    "missingField",
    "unsupportedSchema",
    "unknownTool",
    "invalidToolInput",
    "ambiguousRead",
    "dynamicRead",
    "ambiguousSearch",
    "dynamicDiscovery",
  ]) {
    if (typeof candidate.guidance[key] !== "string") {
      throw new Error("Invalid policy guidance");
    }
  }

  for (const key of ["knownHighVolume", "multipleReads", "broadSearch"]) {
    if (typeof candidate.boundedReads.denyReasons[key] !== "string") {
      throw new Error("Invalid bounded-read decision reason");
    }
  }

  for (const key of [
    "directExposure",
    "metadataAccess",
    "unrestrictedInventory",
    "excessiveNames",
    "genericDiscovery",
    "unsafeOrdering",
  ]) {
    if (typeof candidate.toolDiscovery.denyReasons[key] !== "string") {
      throw new Error("Invalid tool-discovery decision reason");
    }
  }

  return {
    ...candidate,
    mcpNameRegex: new RegExp(candidate.supportedTools.mcpNamePattern, "u"),
  };
}

function countMatches(source, pattern) {
  return Array.from(source.matchAll(pattern)).length;
}

function hasKnownHighVolumeTarget(source, policy) {
  const lowerSource = source.toLowerCase();
  return policy.boundedReads.knownHighVolumeNames.some(
    (name) => lowerSource.includes(name.toLowerCase()),
  ) || policy.boundedReads.knownHighVolumeExtensions.some(
    (extension) => lowerSource.includes(extension.toLowerCase()),
  );
}

function structuredPath(argumentsValue) {
  for (const key of ["path", "file", "filePath", "filename"]) {
    if (key in argumentsValue) {
      return argumentsValue[key];
    }
  }
  return undefined;
}

function hasStructuredBound(argumentsValue) {
  if (Number.isSafeInteger(argumentsValue.limit) && argumentsValue.limit > 0) {
    return true;
  }
  if (Number.isSafeInteger(argumentsValue.length) && argumentsValue.length > 0) {
    return true;
  }
  if (Number.isSafeInteger(argumentsValue.startLine)
      && Number.isSafeInteger(argumentsValue.endLine)
      && argumentsValue.startLine >= 0
      && argumentsValue.endLine >= argumentsValue.startLine) {
    return true;
  }
  return isRecord(argumentsValue.range)
    && Number.isSafeInteger(argumentsValue.range.start)
    && Number.isSafeInteger(argumentsValue.range.end)
    && argumentsValue.range.start >= 0
    && argumentsValue.range.end >= argumentsValue.range.start;
}

function isStructuredReadTool(toolName) {
  const tokens = toolName.toLowerCase().split(/__|_/u);
  return tokens.includes("read")
    || ((tokens.includes("get") || tokens.includes("fetch"))
      && tokens.some((token) => ["file", "content", "text"].includes(token)));
}

function classifyStructuredRead(call, policy) {
  if (!isStructuredReadTool(call.toolName)) {
    return { safe: true };
  }

  const path = structuredPath(call.arguments);
  if (path === undefined) {
    return { guidance: policy.guidance.ambiguousRead };
  }
  if (Array.isArray(path)) {
    return path.length > 1
      ? { deny: policy.boundedReads.denyReasons.multipleReads }
      : { guidance: policy.guidance.ambiguousRead };
  }
  if (typeof path !== "string" || path.length === 0) {
    return { guidance: policy.guidance.ambiguousRead };
  }
  if (/[${}*?]/u.test(path)) {
    return { guidance: policy.guidance.dynamicRead };
  }
  if (hasStructuredBound(call.arguments)) {
    return { safe: true };
  }
  if (hasKnownHighVolumeTarget(path, policy)) {
    return { deny: policy.boundedReads.denyReasons.knownHighVolume };
  }
  return { guidance: policy.guidance.ambiguousRead };
}

function classifyBoundedRead(call, policy) {
  // PostToolUse handles actual truncation of Bash tool results.
  // Structured MCP reads still need pre-execution protection.
  return call.kind === "structured"
    ? classifyStructuredRead(call, policy)
    : { safe: true };
}

function scanJavaScriptSource(source) {
  let codeOnly = "";
  let commentFree = "";
  let state = "code";
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    const next = source[index + 1] ?? "";

    if (state === "line-comment") {
      if (character === "\n" || character === "\r") {
        state = "code";
        codeOnly += character;
        commentFree += character;
      } else {
        codeOnly += " ";
        commentFree += " ";
      }
      continue;
    }
    if (state === "block-comment") {
      if (character === "*" && next === "/") {
        codeOnly += "  ";
        commentFree += "  ";
        index += 1;
        state = "code";
      } else {
        codeOnly += character === "\n" || character === "\r" ? character : " ";
        commentFree += character === "\n" || character === "\r" ? character : " ";
      }
      continue;
    }
    if (state !== "code") {
      commentFree += character;
      codeOnly += character === "\n" || character === "\r" ? character : " ";
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if ((state === "single-quote" && character === "'")
          || (state === "double-quote" && character === "\"")
          || (state === "template" && character === "`")) {
        state = "code";
      }
      continue;
    }

    if (character === "/" && next === "/") {
      codeOnly += "  ";
      commentFree += "  ";
      index += 1;
      state = "line-comment";
    } else if (character === "/" && next === "*") {
      codeOnly += "  ";
      commentFree += "  ";
      index += 1;
      state = "block-comment";
    } else if (character === "'" || character === "\"" || character === "`") {
      state = character === "'"
        ? "single-quote"
        : character === "\"" ? "double-quote" : "template";
      codeOnly += " ";
      commentFree += character;
    } else {
      codeOnly += character;
      commentFree += character;
    }
  }

  return {
    codeOnly,
    commentFree,
    uncertain: state !== "code" && state !== "line-comment",
  };
}

function countIdentifier(source, identifier) {
  const escapedIdentifier = identifier.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return countMatches(source, new RegExp(`\\b${escapedIdentifier}\\b`, "gu"));
}

function findMatchingParenthesis(source, openIndex) {
  let depth = 0;
  let quote = null;
  let escaped = false;

  for (let index = openIndex; index < source.length; index += 1) {
    const character = source[index];
    if (quote !== null) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "'" || character === "\"" || character === "`") {
      quote = character;
    } else if (character === "(") {
      depth += 1;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function skipWhitespace(source, startIndex) {
  let index = startIndex;
  while (index < source.length && /\s/u.test(source[index])) {
    index += 1;
  }
  return index;
}

function extractDirectMethodCall(source, method, startIndex) {
  const token = `.${method}`;
  const methodIndex = skipWhitespace(source, startIndex);
  if (!source.startsWith(token, methodIndex)) {
    return null;
  }
  const afterToken = source[methodIndex + token.length] ?? "";
  if (afterToken !== "(" && !/\s/u.test(afterToken)) {
    return null;
  }
  const openIndex = skipWhitespace(source, methodIndex + token.length);
  if (source[openIndex] !== "(") {
    return { ambiguous: true, methodIndex };
  }
  const closeIndex = findMatchingParenthesis(source, openIndex);
  if (closeIndex < 0) {
    return { ambiguous: true, methodIndex };
  }
  return {
    methodIndex,
    closeIndex,
    nextIndex: closeIndex + 1,
    argument: source.slice(openIndex + 1, closeIndex),
  };
}

function literalStrings(source) {
  const values = [];
  for (const match of source.matchAll(/(["'])([^"'\\]*(?:\\.[^"'\\]*)*)\1/gu)) {
    values.push(match[2]);
  }
  return values;
}

function parseExplicitNameFilter(argument, policy) {
  const arrow = argument.match(
    /^\s*([A-Za-z_$][\w$]*)\s*=>\s*([\s\S]+?)\s*$/u,
  );
  if (arrow === null) {
    return { ambiguous: true };
  }
  const variable = arrow[1];
  let body = arrow[2].trim();
  if (body.startsWith("(") && body.endsWith(")")) {
    body = body.slice(1, -1).trim();
  }
  if (body.includes("&&") || body.includes("?") || body.includes("[")) {
    return { ambiguous: true };
  }

  const terms = body.split(/\s*\|\|\s*/u);
  if (terms.length === 0) {
    return { ambiguous: true };
  }
  const genericTerms = new Set(
    policy.toolDiscovery.genericTerms.map((term) => term.toLowerCase()),
  );
  for (const term of terms) {
    const exactPattern = new RegExp(
      `^${variable.replace(/[$]/gu, "\\$")}\\s*===\\s*([\"'])([^\"']+)\\1$`,
      "u",
    );
    const prefixPattern = new RegExp(
      `^${variable.replace(/[$]/gu, "\\$")}\\.startsWith\\(\\s*([\"'])([^\"']+)\\1\\s*\\)$`,
      "u",
    );
    const match = term.trim().match(exactPattern) ?? term.trim().match(prefixPattern);
    if (match === null) {
      return { ambiguous: true };
    }
    const value = match[2];
    if (value.length === 0) {
      return { unrestricted: true };
    }
    if (genericTerms.has(value.toLowerCase())) {
      return { generic: true };
    }
  }
  return { safe: true };
}

function hasDirectToolExposure(codeOnly) {
  return /\bJSON\.stringify\s*\(\s*ALL_TOOLS\b/iu.test(codeOnly)
    || /\b(?:text|notify|write)\s*\(\s*ALL_TOOLS\b/iu.test(codeOnly)
    || /\bconsole\.log\s*\(\s*ALL_TOOLS\b/iu.test(codeOnly)
    || /\.\.\.\s*ALL_TOOLS\b/iu.test(codeOnly)
    || /\breturn\s+ALL_TOOLS\b/iu.test(codeOnly)
    || /ALL_TOOLS[\s\S]*?\.map\s*\(\s*([A-Za-z_$][\w$]*)\s*=>\s*\1\s*\)/iu.test(codeOnly)
    || /ALL_TOOLS[\s\S]*?\.map\s*\(\s*([A-Za-z_$][\w$]*)\s*=>\s*\(\s*\{\s*\.\.\.\s*\1/iu.test(codeOnly);
}

function hasToolMetadataAccess(codeOnly) {
  return /ALL_TOOLS[\s\S]*?\.(?:map|filter|find|findIndex|some)\s*\([\s\S]*?\.(?:description|schema|inputSchema|parameters|_meta)\b/iu.test(codeOnly)
    || /\bObject\.(?:keys|values|entries)\s*\(\s*ALL_TOOLS\b/iu.test(codeOnly)
    || /ALL_TOOLS\s*\[[^\]]+\]\s*\.(?:description|schema|inputSchema|parameters|_meta)\b/iu.test(codeOnly);
}

function isSafeExactNameAvailability(source) {
  return /^\s*(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*ALL_TOOLS\.some\(\s*([A-Za-z_$][\w$]*)\s*=>\s*\2\.name\s*===\s*(["'])[^"']+\3\s*\)\s*;?\s*text\(\s*\{\s*\1\s*\}\s*\)\s*;?\s*$/u.test(source);
}

function findSummaryOutput(source, namesVariable) {
  const escapedVariable = namesVariable.replace(/[$]/gu, "\\$");
  const explicit = new RegExp(
    `text\\(\\s*\\{\\s*count\\s*:\\s*${escapedVariable}\\.length\\s*,\\s*names\\s*:\\s*${escapedVariable}(?:\\.slice\\(\\s*0\\s*,\\s*(\\d+)\\s*\\))?\\s*\\}\\s*\\)`,
    "u",
  ).exec(source);
  if (explicit !== null) {
    return { match: explicit[0], limit: explicit[1] };
  }
  if (namesVariable === "names") {
    const shorthand = /text\(\s*\{\s*count\s*:\s*names\.length\s*,\s*names\s*\}\s*\)/u.exec(source);
    if (shorthand !== null) {
      return { match: shorthand[0], limit: undefined };
    }
  }
  return null;
}

function hasOtherOutputSink(source, allowedOutput) {
  const withoutAllowed = allowedOutput === null
    ? source
    : source.replace(allowedOutput, "");
  return /\b(?:text|notify|write|console\.log|JSON\.stringify)\s*\(/u.test(withoutAllowed);
}

function classifyToolDiscovery(call, policy) {
  if (call.kind !== "code") {
    return { safe: true };
  }

  const scan = scanJavaScriptSource(call.source);
  const actualReferences = countIdentifier(scan.codeOnly, "ALL_TOOLS");
  if (actualReferences === 0) {
    const dynamicReference = /\b(?:globalThis|Reflect\.get|eval)\b[\s\S]*["']ALL_TOOLS["']/u.test(scan.commentFree)
      || /["']ALL_["']\s*\+\s*["']TOOLS["']/u.test(scan.commentFree)
      || /\$\{[^}]*\bALL_TOOLS\b[^}]*\}/u.test(scan.commentFree);
    return dynamicReference
      ? { guidance: policy.guidance.dynamicDiscovery }
      : { safe: true };
  }

  if (scan.uncertain) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }
  if (/\/(?:\\.|[^/\r\n])*\bALL_TOOLS\b(?:\\.|[^/\r\n])*\/[dgimsuvy]*/u.test(scan.commentFree)) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }
  if (hasDirectToolExposure(scan.codeOnly)) {
    return { deny: policy.toolDiscovery.denyReasons.directExposure };
  }
  if (hasToolMetadataAccess(scan.codeOnly)) {
    return { deny: policy.toolDiscovery.denyReasons.metadataAccess };
  }

  const allToolsIndex = scan.codeOnly.indexOf("ALL_TOOLS");

  if (actualReferences === 1 && isSafeExactNameAvailability(scan.commentFree)) {
    return { safe: true };
  }
  if (/ALL_TOOLS\s*\[/u.test(scan.codeOnly)
      || /=\s*ALL_TOOLS\s*;/u.test(scan.codeOnly)
      || actualReferences > 1) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }
  const assignment = scan.commentFree.slice(0, allToolsIndex).match(
    /(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*$/u,
  );
  if (assignment === null) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }
  const namesVariable = assignment[1];
  const chainStart = allToolsIndex + "ALL_TOOLS".length;
  for (const method of ["find", "findIndex"]) {
    const descriptorSearch = extractDirectMethodCall(
      scan.commentFree,
      method,
      chainStart,
    );
    if (descriptorSearch !== null) {
      return descriptorSearch.ambiguous
        ? { guidance: policy.guidance.dynamicDiscovery }
        : { deny: policy.toolDiscovery.denyReasons.unsafeOrdering };
    }
  }
  const rootFilter = extractDirectMethodCall(scan.commentFree, "filter", chainStart);
  if (rootFilter !== null) {
    return rootFilter.ambiguous
      ? { guidance: policy.guidance.dynamicDiscovery }
      : { deny: policy.toolDiscovery.denyReasons.unsafeOrdering };
  }
  const rootSlice = extractDirectMethodCall(scan.commentFree, "slice", chainStart);
  if (rootSlice !== null) {
    return rootSlice.ambiguous
      ? { guidance: policy.guidance.dynamicDiscovery }
      : { deny: policy.toolDiscovery.denyReasons.directExposure };
  }
  const mapCall = extractDirectMethodCall(scan.commentFree, "map", chainStart);
  if (mapCall === null || mapCall.ambiguous) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }

  const mapArrow = mapCall.argument.match(
    /^\s*([A-Za-z_$][\w$]*)\s*=>\s*\1\.name\s*$/u,
  );
  if (mapArrow === null) {
    return /\.(?:description|schema|inputSchema|parameters|_meta)\b/iu.test(mapCall.argument)
      ? { deny: policy.toolDiscovery.denyReasons.metadataAccess }
      : { guidance: policy.guidance.dynamicDiscovery };
  }
  const filterCall = extractDirectMethodCall(
    scan.commentFree,
    "filter",
    mapCall.nextIndex,
  );
  if (filterCall === null) {
    return { deny: policy.toolDiscovery.denyReasons.unrestrictedInventory };
  }
  if (filterCall.ambiguous) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }

  const genericTerms = new Set(
    policy.toolDiscovery.genericTerms.map((term) => term.toLowerCase()),
  );
  if (literalStrings(filterCall.argument).some(
    (value) => genericTerms.has(value.toLowerCase()),
  )) {
    return { deny: policy.toolDiscovery.denyReasons.genericDiscovery };
  }
  const parsedFilter = parseExplicitNameFilter(filterCall.argument, policy);
  if (parsedFilter.generic) {
    return { deny: policy.toolDiscovery.denyReasons.genericDiscovery };
  }
  if (parsedFilter.unrestricted) {
    return { deny: policy.toolDiscovery.denyReasons.unrestrictedInventory };
  }
  if (!parsedFilter.safe) {
    return { guidance: policy.guidance.dynamicDiscovery };
  }

  const pipelineSlice = extractDirectMethodCall(
    scan.commentFree,
    "slice",
    filterCall.nextIndex,
  );
  let pipelineLimit;
  if (pipelineSlice !== null) {
    if (pipelineSlice.ambiguous) {
      return { guidance: policy.guidance.dynamicDiscovery };
    }
    const limitMatch = pipelineSlice.argument.match(/^\s*0\s*,\s*(\d+)\s*$/u);
    if (limitMatch === null) {
      return { guidance: policy.guidance.dynamicDiscovery };
    }
    pipelineLimit = Number(limitMatch[1]);
  }
  const chainEnd = skipWhitespace(
    scan.commentFree,
    pipelineSlice === null ? filterCall.nextIndex : pipelineSlice.nextIndex,
  );
  if (scan.commentFree[chainEnd] !== ";") {
    return { guidance: policy.guidance.dynamicDiscovery };
  }

  const summary = findSummaryOutput(scan.commentFree, namesVariable);
  if (summary === null || hasOtherOutputSink(scan.commentFree, summary.match)) {
    return { deny: policy.toolDiscovery.denyReasons.directExposure };
  }
  const outputLimit = summary.limit === undefined ? undefined : Number(summary.limit);
  for (const limit of [pipelineLimit, outputLimit]) {
    if (limit !== undefined && limit > policy.toolDiscovery.maxNames) {
      return { deny: policy.toolDiscovery.denyReasons.excessiveNames };
    }
  }
  if (pipelineLimit === undefined && outputLimit === undefined) {
    return { deny: policy.toolDiscovery.denyReasons.unrestrictedInventory };
  }
  return { safe: true };
}

async function loadPolicy() {
  const text = await readFile(POLICY_URL, "utf8");
  return validatePolicy(JSON.parse(text));
}

async function readBoundedStdin(maxInputBytes) {
  const chunks = [];
  let bytes = 0;
  let oversized = false;

  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > maxInputBytes) {
      oversized = true;
      continue;
    }
    chunks.push(chunk);
  }

  return {
    oversized,
    text: oversized ? "" : Buffer.concat(chunks).toString("utf8"),
  };
}

function normalizeToolCall(input, policy) {
  const schemaVersion = input.schema_version ?? policy.inputSchemaVersion;
  if (schemaVersion !== policy.inputSchemaVersion) {
    return { guidance: policy.guidance.unsupportedSchema };
  }

  if (typeof input.hook_event_name !== "string") {
    return { guidance: policy.guidance.missingField };
  }
  if (input.hook_event_name !== "PreToolUse") {
    return { irrelevant: true };
  }
  if (typeof input.tool_name !== "string" || input.tool_name.length === 0
      || !("tool_input" in input)) {
    return { guidance: policy.guidance.missingField };
  }

  const toolName = input.tool_name;
  const toolInput = input.tool_input;

  if (policy.supportedTools.shell.includes(toolName)) {
    if (!isRecord(toolInput) || typeof toolInput.command !== "string") {
      return { guidance: policy.guidance.invalidToolInput };
    }
    return { call: { kind: "shell", toolName, source: toolInput.command } };
  }

  if (policy.supportedTools.code.includes(toolName)) {
    if (typeof toolInput === "string") {
      return { call: { kind: "code", toolName, source: toolInput } };
    }
    if (isRecord(toolInput) && typeof toolInput.code === "string") {
      return { call: { kind: "code", toolName, source: toolInput.code } };
    }
    return { guidance: policy.guidance.invalidToolInput };
  }

  if (policy.mcpNameRegex.test(toolName)) {
    if (!isRecord(toolInput)) {
      return { guidance: policy.guidance.invalidToolInput };
    }
    return { call: { kind: "structured", toolName, arguments: toolInput } };
  }

  return { guidance: policy.guidance.unknownTool };
}

async function main() {
  let policy;
  try {
    policy = await loadPolicy();
  } catch {
    writeGuidance(FALLBACK_GUIDANCE);
    return;
  }

  const input = await readBoundedStdin(policy.maxInputBytes);
  if (input.oversized) {
    writeGuidance(policy.guidance.oversizedInput, policy.maxGuidanceChars);
    return;
  }

  let envelope;
  try {
    envelope = JSON.parse(input.text);
  } catch {
    writeGuidance(policy.guidance.malformedJson, policy.maxGuidanceChars);
    return;
  }

  if (!isRecord(envelope)) {
    writeGuidance(policy.guidance.missingField, policy.maxGuidanceChars);
    return;
  }

  const normalized = normalizeToolCall(envelope, policy);
  if (normalized.guidance) {
    writeGuidance(normalized.guidance, policy.maxGuidanceChars);
    return;
  }
  if (normalized.irrelevant) {
    return;
  }

  const boundedRead = classifyBoundedRead(normalized.call, policy);
  if (boundedRead.deny) {
    writeDeny(boundedRead.deny, policy.maxDecisionReasonChars);
    return;
  }
  if (boundedRead.guidance) {
    writeGuidance(boundedRead.guidance, policy.maxGuidanceChars);
    return;
  }

  const toolDiscovery = classifyToolDiscovery(normalized.call, policy);
  if (toolDiscovery.deny) {
    writeDeny(toolDiscovery.deny, policy.maxDecisionReasonChars);
  } else if (toolDiscovery.guidance) {
    writeGuidance(toolDiscovery.guidance, policy.maxGuidanceChars);
  }
}

await main();
