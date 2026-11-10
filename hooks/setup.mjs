import {
  lstatSync, mkdirSync, realpathSync, symlinkSync, unlinkSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Only machine-independent commands are stored in the versioned hooks.json.
const hooksRoot = dirname(fileURLToPath(import.meta.url));
const checkoutRoot = resolve(hooksRoot, "..");
const home = process.env.CODEX_HOME
  ? resolve(process.env.CODEX_HOME)
  : join(homedir(), ".codex");
const nodeName = process.platform === "win32"
  ? "codex-customization-node.exe"
  : "codex-customization-node";
const links = [
  { name: "hooks.json", target: join(hooksRoot, "hooks.json"), type: "file" },
  {
    name: "AGENTS.md",
    target: join(checkoutRoot, "resources", "AGENTS.md"),
    type: "file",
  },
  { name: "codex-customization-hooks", target: hooksRoot, type: "dir" },
  { name: nodeName, target: realpathSync(process.execPath), type: "file" },
].map((entry) => ({ ...entry, dest: join(home, entry.name) }));
const nodeLink = links.find((link) => link.name === nodeName);

function state(entry) {
  let stat;
  try {
    stat = lstatSync(entry.dest);
  } catch (error) {
    if (error?.code === "ENOENT") return "missing";
    throw error;
  }
  if (!stat.isSymbolicLink()) return "conflict";
  try {
    // Works for Windows junctions and symlinks, including NT path prefixes.
    const actual = realpathSync(entry.dest);
    const expected = realpathSync(entry.target);
    const normalize = (path) => process.platform === "win32"
      ? path.toLowerCase() : path;
    return normalize(actual) === normalize(expected) ? "linked" : "conflict";
  } catch {
    return "conflict"; // Never remove a dangling or unresolvable link.
  }
}

function checkOwnership() {
  for (const link of links) {
    if (state(link) === "conflict") {
      throw new Error("Refusing unexpected path: " + link.dest);
    }
  }
}

function install() {
  checkOwnership();
  mkdirSync(home, { recursive: true });
  const created = [];
  try {
    for (const link of links) {
      if (state(link) === "linked") continue;
      symlinkSync(link.target, link.dest, link.type);
      created.push(link);
      if (state(link) !== "linked") {
        throw new Error("Link verification failed: " + link.dest);
      }
    }
  } catch (error) {
    // Never remove existing user state, even if a partially created link fails.
    for (const link of created.reverse()) {
      if (state(link) === "linked") unlinkSync(link.dest);
    }
    throw error;
  }
  console.log("Installed Codex resources from: " + checkoutRoot);
  console.log("Pinned Node executable: " + nodeLink.target);
  console.log("Open Codex CLI with this CODEX_HOME and approve hooks via /hooks.");
  console.log("IDEA ACP cannot approve hooks; start a fresh IDEA chat afterward.");
}

function uninstall() {
  checkOwnership();
  for (const link of links) {
    if (state(link) === "linked") unlinkSync(link.dest);
  }
  console.log("Owned customization links removed; unrelated Codex files retained.");
}

function status() {
  for (const link of links) console.log(link.name + ": " + state(link));
}

const action = process.argv[2] ?? "status";
try {
  if (action === "install") install();
  else if (action === "uninstall") uninstall();
  else if (action === "status") status();
  else throw new Error("Usage: node hooks/setup.mjs install|status|uninstall");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
