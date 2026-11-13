/** Code Mode self-test (public repo version).
 *  Requires a live environment when HERMES_HOME is set:
 *    HERMES_HOME=C:/Users/User/AppData/Local/hermes  (with .env: N8N_API_KEY etc.)
 *    DEMO_WF_ID=<n8n workflow id with a code node "Build CSV">  (enables live checks 10-12)
 *  Without HERMES_HOME only sandbox/static checks run.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HERMES_HOME = process.env.HERMES_HOME || "";
const ENV_FILE = HERMES_HOME ? path.join(HERMES_HOME, ".env") : null;
const LIVE = HERMES_HOME && fs.existsSync(ENV_FILE);
const DEMO_WF_ID = process.env.DEMO_WF_ID || "";
const CODE_FILE = process.env.DEMO_CODE_FILE || "";

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [path.join(__dirname, "server.js"), "--registry", path.join(__dirname, "registry.json"), ...(ENV_FILE ? ["--env-file", ENV_FILE] : [])]
});
const client = new Client({ name: "selftest", version: "1.0.0" });
await client.connect(transport);
const results = [];
const check = (name, cond, extra = "") => results.push(`${cond ? "PASS" : "FAIL"} ${name}${extra ? " — " + extra : ""}`);

// 1-2. handshake + search
const { tools } = await client.callTool({ name: "search", arguments: { query: "n8n" } }).then(async () => await client.listTools()).catch(() => ({ tools: [] }));
check("handshake+tools/list", tools.length === 2, `tools=${tools.map((t) => t.name).join(",")}`);
const s1 = JSON.parse((await client.callTool({ name: "search", arguments: { query: "n8n workflow create" } })).content[0].text);
check("search returns full signatures", s1.matched >= 1 && s1.methods[0].params.length >= 2);

// 3. sandbox sealed
for (const probe of [
  ["require", "return require('fs').readFileSync('x','utf8');"],
  ["process", "return process.env;"],
  ["fetch", "return (await fetch('http://x')).status;"]
]) {
  const r = JSON.parse((await client.callTool({ name: "execute", arguments: { js_code: probe[1] } })).content[0].text);
  check(`sandbox blocks ${probe[0]}`, r.status === "error");
}

// 4. confirm gate
const g = JSON.parse((await client.callTool({ name: "execute", arguments: { js_code: "await mcp.n8n.deleteWorkflow({id:'x'});" } })).content[0].text);
check("confirm-gate blocks write", g.status === "confirmation_required");

if (LIVE) {
  // 5. read works
  const r1 = JSON.parse((await client.callTool({ name: "execute", arguments: { js_code: "return await mcp.n8n.listWorkflows({limit:5});" } })).content[0].text);
  check("execute read ok", r1.status === "ok" && Array.isArray(r1.result?.data));

  // 6. verifyNodeCode/exportWorkflowSafe in registry (hot-reload check needs the methods present)
  const s3 = JSON.parse((await client.callTool({ name: "search", arguments: { query: "verify node code export safe" } })).content[0].text);
  check("verify/export methods present", s3.methods.some((x) => x.method === "verifyNodeCode") && s3.methods.some((x) => x.method === "exportWorkflowSafe"));

  if (DEMO_WF_ID && CODE_FILE) {
    // 7. set → sha256 → verify roundtrip
    const set = JSON.parse((await client.callTool({ name: "execute", arguments: { confirm: true, js_code: `return await mcp.n8n.setNodeCode({id:${JSON.stringify(DEMO_WF_ID)},nodeName:"Build CSV",codeFile:${JSON.stringify(CODE_FILE)}});` } })).content[0].text);
    check("setNodeCode returns sha256", /^[0-9a-f]{16}$/.test(set.result?.sha256 || ""));
    const ver = JSON.parse((await client.callTool({ name: "execute", arguments: { js_code: `return await mcp.n8n.verifyNodeCode({id:${JSON.stringify(DEMO_WF_ID)},nodeName:"Build CSV",codeFile:${JSON.stringify(CODE_FILE)}});` } })).content[0].text);
    check("verifyNodeCode match:true", ver.result?.match === true);
    // 8. export sanitizer
    const exp = JSON.parse((await client.callTool({ name: "execute", arguments: { js_code: `return await mcp.n8n.exportWorkflowSafe({id:${JSON.stringify(DEMO_WF_ID)}});` } })).content[0].text);
    check("exportWorkflowSafe sanitizes", exp.result && !exp.result.workflow.shared && Array.isArray(exp.result.redactions));
    // 9. raw-secret write refused
    const KEY = fs.readFileSync(ENV_FILE, "utf8").match(/^N8N_API_KEY=(.*)$/m)?.[1] || "";
    const guard = JSON.parse((await client.callTool({ name: "execute", arguments: { confirm: true, js_code: `try { await mcp.n8n.updateWorkflow({id:${JSON.stringify(DEMO_WF_ID)},name:${JSON.stringify(KEY)}}); return {blocked:false}; } catch(e) { return {blocked:/Refusing to embed raw secret/.test(String(e.message))}; }` } })).content[0].text);
    check("secret guard blocks raw key write", guard.result?.blocked === true);
  } else {
    console.log("SKIP live workflow checks: set DEMO_WF_ID and DEMO_CODE_FILE");
  }
} else {
  console.log("SKIP live checks: set HERMES_HOME to enable");
}

console.log(results.join("\n"));
await client.close();
process.exit(results.some((r) => r.startsWith("FAIL")) ? 1 : 0);
