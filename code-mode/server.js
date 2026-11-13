#!/usr/bin/env node
/**
 * Code Mode MCP server for Hermes Agent Hub.
 * Two tools only:
 *   search(query)      -> full signatures of matching registry methods
 *   execute(js, confirm) -> run JS in a sandbox; mcp.<server>.<method>() adapters
 *                           are the only door outside; write/delete methods
 *                           require confirm=true (user's explicit "да" upstream).
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- CLI args ----------
function argValue(flag) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : null;
}
const REGISTRY_PATH = path.resolve(argValue("--registry") || path.join(__dirname, "registry.json"));
const ENV_FILE = argValue("--env-file"); // Hermes .env (for N8N_API_KEY)
const EXEC_LOG = path.resolve(argValue("--exec-log") || path.join(__dirname, "exec.log"));
const EXEC_TIMEOUT_MS = 60_000;
const RESULT_CAP = 100_000;

// ---------- registry (hot-reloadable) ----------
let registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, "utf8"));
let METHOD_RE = [];
function rebuildMethodIndex() {
  METHOD_RE = allMethods().map((m) => ({
    re: new RegExp(`mcp\\s*\\.\\s*${m.server}\\s*\\.\\s*${m.name}\\s*\\(`, "g"),
    ...m
  }));
}
try {
  fs.watch(REGISTRY_PATH, () => {
    setTimeout(() => {
      try {
        registry = JSON.parse(fs.readFileSync(REGISTRY_PATH, "utf8"));
        rebuildMethodIndex();
        console.error(`code-mode: registry reloaded (${allMethods().length} methods)`);
      } catch (e) {
        console.error(`code-mode: registry reload failed: ${e.message}`);
      }
    }, 250); // debounce editor write races
  });
} catch {
  /* watch is best-effort */
}

// ---------- secrets (never logged, never returned) ----------
const secrets = {};
if (ENV_FILE && fs.existsSync(ENV_FILE)) {
  for (const line of fs.readFileSync(ENV_FILE, "utf8").split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) secrets[m[1]] = m[2];
  }
}

// ---------- exec log ----------
function logExec(entry) {
  try {
    fs.appendFileSync(EXEC_LOG, JSON.stringify(entry) + "\n", "utf8");
  } catch {
    /* logging must never break execution */
  }
}
const codeHash = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);

// ---------- helpers: flatten registry ----------
function allMethods() {
  const out = [];
  for (const [server, def] of Object.entries(registry.servers)) {
    for (const m of def.methods) {
      out.push({ server, serverConfigured: !!def.configured, ...m });
    }
  }
  return out;
}
rebuildMethodIndex();

// ---------- secret guard ----------
// Server knows its own secrets (from .env): refuse to WRITE any of them verbatim
// into n8n workflows — the workflow must carry a reference (={{$env.NAME}}), not the value.
function findRawSecrets(payload) {
  const s = JSON.stringify(payload ?? "");
  const hits = [];
  for (const [name, value] of Object.entries(secrets)) {
    if (value && value.length >= 12 && s.includes(value)) hits.push(name);
  }
  return hits;
}

// Secret-looking patterns for EXPORT sanitizing (values we may not know).
const SECRET_PATTERNS = [
  [/pza_[A-Za-z0-9_]{8,}/g, "pza_REDACTED"],
  [/github_pat_[A-Za-z0-9_]{20,}/g, "github_pat_REDACTED"],
  [/ghp_[A-Za-z0-9]{20,}/g, "ghp_REDACTED"],
  [/sk-[A-Za-z0-9]{16,}/g, "sk-REDACTED"],
  [/Bearer\s+[A-Za-z0-9_\-\.]{16,}/g, "Bearer REDACTED"]
];
function sanitizeForExport(obj) {
  const redactions = [];
  const out = JSON.parse(JSON.stringify(obj, (k, v) => {
    if (typeof v !== "string") return v;
    let s = v;
    for (const [re, repl] of SECRET_PATTERNS) {
      if (re.test(s)) { redactions.push(String(re).slice(1, -2)); s = s.replace(re, repl); }
      re.lastIndex = 0;
    }
    return s;
  }));
  if (out.shared) { delete out.shared; redactions.push("shared (owner personal data)"); }
  return { workflow: out, redactions: [...new Set(redactions)] };
}

function searchMethods(query) {
  const tokens = String(query || "")
    .toLowerCase()
    .split(/[^a-z0-9а-яё_]+/i)
    .filter((t) => t.length > 1);
  if (!tokens.length) return allMethods();
  const scored = allMethods()
    .map((m) => {
      const hay = `${m.server} ${m.name} ${m.description} ${(m.tags || []).join(" ")}`.toLowerCase();
      let score = 0;
      for (const t of tokens) {
        if (m.name.toLowerCase().includes(t)) score += 5;
        if (m.server === t) score += 3;
        if ((m.tags || []).some((tag) => tag.includes(t))) score += 3;
        if (hay.includes(t)) score += 1;
      }
      return { m, score };
    })
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score);
  return scored.map((x) => x.m);
}

function signature(m) {
  return {
    server: m.server,
    method: m.name,
    call: `mcp.${m.server}.${m.name}(${(m.params || []).map((p) => (p.required ? p.name : `${p.name}=?`)).join(", ")})`,
    description: m.description,
    danger: m.danger,
    configured: m.serverConfigured,
    params: m.params || [],
    returns: m.returns
  };
}

// ---------- HTTP adapters (the ONLY door outside) ----------
async function httpJson(url, { method = "GET", headers = {}, body } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 30_000);
  try {
    const res = await fetch(url, {
      method,
      headers: { Accept: "application/json", ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined,
      signal: ctrl.signal
    });
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = text.slice(0, 2000); }
    if (!res.ok) {
      const err = new Error(`HTTP ${res.status}: ${typeof data === "string" ? data : JSON.stringify(data).slice(0, 500)}`);
      err.statusCode = res.status;
      err.body = data;
      throw err;
    }
    return data;
  } finally {
    clearTimeout(t);
  }
}

// n8n Public API v1 mapping
const n8nCall = {
  listWorkflows: (a) => ({ path: `/workflows?limit=${a?.limit ?? 100}` }),
  getWorkflow: (a) => ({ path: `/workflows/${a.id}` }),
  createWorkflow: (a) => ({ path: `/workflows`, method: "POST", body: { name: a.name, nodes: a.nodes, connections: a.connections, settings: a.settings ?? {} } }),
  updateWorkflow: (a) => ({ path: `/workflows/${a.id}`, method: "PUT", body: { name: a.name, nodes: a.nodes, connections: a.connections, settings: a.settings ?? {} } }),
  deleteWorkflow: (a) => ({ path: `/workflows/${a.id}`, method: "DELETE" }),
  activateWorkflow: (a) => ({ path: `/workflows/${a.id}/activate`, method: "POST" }),
  deactivateWorkflow: (a) => ({ path: `/workflows/${a.id}/deactivate`, method: "POST" }),
  listExecutions: (a) => ({ path: `/executions?limit=${a?.limit ?? 20}` }),
  getExecution: (a) => ({ path: `/executions/${a.id}` })
};

// GitHub REST v3 mapping
const githubCall = {
  listIssues: (a) => ({ path: `/repos/${a.repo}/issues?state=${a?.state ?? "open"}&per_page=${a?.limit ?? 30}` }),
  getIssue: (a) => ({ path: `/repos/${a.repo}/issues/${a.number}` }),
  createIssue: (a) => ({ path: `/repos/${a.repo}/issues`, method: "POST", body: { title: a.title, body: a.body ?? "", labels: a.labels ?? [] } })
};

function makeAdapter(serverName, def) {
  const base = def.baseUrl.replace(/\/$/, "");
  const adapter = {};
  for (const m of def.methods) {
    adapter[m.name] = async (args = {}) => {
      if (!def.configured) {
        throw new Error(`Server "${serverName}" is not configured (no credentials connected). Method ${m.name} is search-only for now.`);
      }
      if (serverName === "n8n") {
        const n8nHeaders = { "X-N8N-API-KEY": secrets.N8N_API_KEY || "" };
        const guardWrites = (payload) => {
          const hits = findRawSecrets(payload);
          if (hits.length) {
            throw new Error(`Refusing to embed raw secret(s) [${hits.join(", ")}] into n8n workflow. Use a reference (={{$env.NAME}}) instead — the server injects nothing, n8n reads $env at runtime.`);
          }
        };
        if (m.name === "setNodeCode") {
          // Read the code file SERVER-side: the LLM never re-types the JS body,
          // so quote escaping cannot be corrupted in transit.
          const wf = await httpJson(`${base}/api/v1/workflows/${args.id}`, { headers: n8nHeaders });
          const node = (wf.nodes || []).find((n) => n.name === args.nodeName && n.type === "n8n-nodes-base.code");
          if (!node) throw new Error(`Code node "${args.nodeName}" not found in workflow ${args.id}`);
          const code = fs.readFileSync(path.resolve(args.codeFile), "utf8");
          guardWrites(code);
          node.parameters.jsCode = code;
          await httpJson(`${base}/api/v1/workflows/${args.id}`, {
            method: "PUT", headers: n8nHeaders,
            body: { name: wf.name, nodes: wf.nodes, connections: wf.connections, settings: wf.settings || {} }
          });
          return { updated: true, node: args.nodeName, codeLength: code.length, sha256: crypto.createHash("sha256").update(code).digest("hex").slice(0, 16) };
        }
        if (m.name === "verifyNodeCode") {
          // Server-side objective truth: compare the node's ACTUAL jsCode against the file.
          const wf = await httpJson(`${base}/api/v1/workflows/${args.id}`, { headers: n8nHeaders });
          const node = (wf.nodes || []).find((n) => n.name === args.nodeName && n.type === "n8n-nodes-base.code");
          if (!node) throw new Error(`Code node "${args.nodeName}" not found in workflow ${args.id}`);
          const expected = fs.readFileSync(path.resolve(args.codeFile), "utf8");
          const actual = node.parameters.jsCode ?? "";
          const h = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 16);
          return { match: actual === expected, actualSha256: h(actual), expectedSha256: h(expected), actualLength: actual.length, expectedLength: expected.length };
        }
        if (m.name === "exportWorkflowSafe") {
          const wf = await httpJson(`${base}/api/v1/workflows/${args.id}`, { headers: n8nHeaders });
          const rawHits = findRawSecrets(wf);
          const { workflow, redactions } = sanitizeForExport(wf);
          return { workflow, redactions, rawSecretsFound: rawHits, safeToPublish: rawHits.length === 0 };
        }
        const spec = n8nCall[m.name]?.(args);
        if (!spec) throw new Error(`No HTTP mapping for n8n.${m.name}`);
        if (spec.body && (m.name === "createWorkflow" || m.name === "updateWorkflow")) guardWrites(spec.body);
        return httpJson(`${base}/api/v1${spec.path}`, {
          method: spec.method,
          headers: n8nHeaders,
          body: spec.body
        });
      }
      if (serverName === "github") {
        const spec = githubCall[m.name]?.(args);
        if (!spec) throw new Error(`No HTTP mapping for github.${m.name}`);
        return httpJson(`${base}${spec.path}`, {
          method: spec.method,
          headers: {
            Authorization: `Bearer ${secrets.GITHUB_TOKEN || ""}`,
            Accept: "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
          },
          body: spec.body
        });
      }
      throw new Error(`Adapter for "${serverName}" not implemented`);
    };
  }
  return adapter;
}

// ---------- sandbox ----------
function buildSandboxAdapter() {
  const mcpObj = {};
  const callLedger = []; // every adapter call, for logging
  for (const [serverName, def] of Object.entries(registry.servers)) {
    const adapter = makeAdapter(serverName, def);
    mcpObj[serverName] = {};
    for (const [methodName, fn] of Object.entries(adapter)) {
      mcpObj[serverName][methodName] = async (args) => {
        const started = Date.now();
        try {
          const result = await fn(args);
          callLedger.push({ server: serverName, method: methodName, ok: true, ms: Date.now() - started });
          return result;
        } catch (e) {
          callLedger.push({ server: serverName, method: methodName, ok: false, error: String(e.message || e).slice(0, 300), ms: Date.now() - started });
          throw e;
        }
      };
    }
  }
  return { mcpObj, callLedger };
}

async function runSandbox(code) {
  const { mcpObj, callLedger } = buildSandboxAdapter();
  const consoleLines = [];
  const sandboxConsole = {
    log: (...a) => consoleLines.push(a.map(String).join(" ").slice(0, 2000)),
    error: (...a) => consoleLines.push("[stderr] " + a.map(String).join(" ").slice(0, 2000)),
    warn: (...a) => consoleLines.push("[warn] " + a.map(String).join(" ").slice(0, 2000))
  };
  const sandbox = {
    mcp: mcpObj,
    Promise, JSON, Math, Date, Object, Array, String, Number, Boolean, Map, Set,
    isNaN, parseInt, parseFloat, // primitives only; no host objects
    console: sandboxConsole
  };
  // NOTE: vm context gets exactly the keys above. No require/process/fs/fetch/Buffer/timers.
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  const wrapped = `(async () => {\n${code}\n})()`;
  const promise = vm.runInContext(wrapped, context, { timeout: EXEC_TIMEOUT_MS, displayErrors: true });
  const result = await Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`Sandbox timeout after ${EXEC_TIMEOUT_MS}ms`)), EXEC_TIMEOUT_MS + 1000))
  ]);
  return { result, callLedger, consoleLines };
}

function capValue(x) {
  // Keep the envelope JSON-valid: if the result is huge, degrade it to a capped string.
  let s;
  try { s = typeof x === "string" ? x : JSON.stringify(x, null, 1); } catch { s = String(x); }
  if (s === undefined) return "undefined";
  if (s.length <= RESULT_CAP) return x;
  return s.slice(0, RESULT_CAP) + `\n...[truncated ${s.length - RESULT_CAP} chars]`;
}

// ---------- MCP server ----------
const server = new McpServer(
  { name: "code-mode", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.tool(
  "search",
  "Search the Code Mode method registry (by name/description/tags/server). Returns FULL signatures of matching methods: call syntax, params with types and required flags, danger level, configured flag.",
  { query: z.string().describe("Free-text query, e.g. 'n8n create workflow' or 'github issue'") },
  async ({ query }) => {
    const found = searchMethods(query);
    const payload = {
      matched: found.length,
      hint: found.length ? undefined : "No match. Try broader tokens like the server name (n8n/github/notion/gsheets) or an action word (create/list/get).",
      methods: found.map(signature)
    };
    return { content: [{ type: "text", text: JSON.stringify(payload, null, 1) }] };
  }
);

server.tool(
  "execute",
  "Execute JavaScript in a sandbox. Only `mcp.<server>.<method>(args)` adapters may reach the outside (found via search()). Sequential awaits and Promise.all() are supported; no LLM round-trips between calls. Write/delete methods require confirm=true — set it ONLY after the user's explicit approval.",
  {
    js_code: z.string().describe("JS body; top-level await allowed; return a value to get it back"),
    confirm: z.boolean().default(false).describe("Must be true when the code calls write/delete methods; keep false otherwise")
  },
  async ({ js_code, confirm = false }) => {
    const started = Date.now();
    const hash = codeHash(js_code);
    // static scan: which registry methods does the code reference?
    const referenced = METHOD_RE.filter((m) => {
      m.re.lastIndex = 0;
      return m.re.test(js_code);
    });
    const dangerous = referenced.filter((m) => m.danger === "write" || m.danger === "delete");
    const base = { ts: new Date().toISOString(), codeHash: hash, referenced: referenced.map((m) => `${m.server}.${m.name}`) };

    if (dangerous.length && confirm !== true) {
      const entry = { ...base, status: "confirmation_required", dangerous: dangerous.map((m) => `${m.server}.${m.name} (${m.danger})`), ms: Date.now() - started };
      logExec(entry);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            status: "confirmation_required",
            dangerous_methods: entry.dangerous,
            message: "Code calls write/delete methods. Get the user's explicit approval first, then re-call execute with confirm=true."
          }, null, 1)
        }],
        isError: false
      };
    }

    try {
      const { result, callLedger, consoleLines } = await runSandbox(js_code);
      logExec({ ...base, status: "ok", confirm: !!confirm, calls: callLedger, ms: Date.now() - started });
      return {
        content: [{
          type: "text",
          text: JSON.stringify({ status: "ok", result: capValue(result), calls: callLedger, console: consoleLines }, null, 1)
        }]
      };
    } catch (e) {
      logExec({ ...base, status: "error", confirm: !!confirm, error: String(e?.message || e).slice(0, 500), ms: Date.now() - started });
      return {
        content: [{ type: "text", text: JSON.stringify({ status: "error", error: String(e?.message || e).slice(0, RESULT_CAP) }) }],
        isError: true
      };
    }
  }
);

// ---------- startup ----------
const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`code-mode MCP up: registry=${REGISTRY_PATH} methods=${allMethods().length} n8nConfigured=${!!registry.servers.n8n?.configured} keyPresent=${!!secrets.N8N_API_KEY}`);
