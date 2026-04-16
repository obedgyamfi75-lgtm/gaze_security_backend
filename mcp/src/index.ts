import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const API_BASE = process.env.GAZESEC_API_URL ?? "http://localhost:5000";
const API_KEY = process.env.GAZESEC_API_KEY ?? "";

async function apiRequest(
  method: string,
  path: string,
  body?: Record<string, unknown>
): Promise<unknown> {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${API_KEY}`,
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(data?.message ?? data?.error ?? `HTTP ${res.status}`);
  }

  return data;
}

function ok(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function err(e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  return {
    content: [{ type: "text" as const, text: `Error: ${msg}` }],
  };
}

const server = new McpServer({ name: "gazesec", version: "1.0.0" });

// ── Assessments ──────────────────────────────────────────────────────────────

server.tool(
  "create_assessment",
  "Create a new security assessment in GazeSec.",
  {
    name: z.string().describe("Assessment name"),
    assessment_type: z.enum([
      "vulnerability_assessment",
      "penetration_test",
      "code_review",
      "configuration_review",
      "compliance_audit",
      "red_team",
      "bug_bounty",
    ]).default("vulnerability_assessment").describe("Type of assessment"),
    description: z.string().optional().describe("Assessment description"),
    scope: z.string().optional().describe("Scope of the assessment"),
    asset_id: z.string().optional().describe("Asset UUID to associate with"),
  },
  async ({ name, assessment_type, description, scope, asset_id }) => {
    try {
      const data = await apiRequest("POST", "/api/assessments/new", {
        name,
        assessment_type,
        description,
        scope_description: scope,
        asset_id,
      });
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "start_assessment",
  "Start an assessment — sets status to in_progress.",
  { assessment_id: z.string().describe("Assessment UUID") },
  async ({ assessment_id }) => {
    try {
      const data = await apiRequest("POST", `/api/assessments/${assessment_id}/start`);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "complete_assessment",
  "Mark an assessment as completed.",
  {
    assessment_id: z.string().describe("Assessment UUID"),
    executive_summary: z.string().optional().describe("Executive summary of findings"),
  },
  async ({ assessment_id, executive_summary }) => {
    try {
      const data = await apiRequest("POST", `/api/assessments/${assessment_id}/complete`, {
        executive_summary,
      });
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment",
  "Get details of an assessment.",
  { assessment_id: z.string().describe("Assessment UUID") },
  async ({ assessment_id }) => {
    try {
      const data = await apiRequest("GET", `/api/assessments/${assessment_id}`);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "list_assessments",
  "List all assessments.",
  {},
  async () => {
    try {
      const data = await apiRequest("GET", "/api/assessments/");
      return ok(data);
    } catch (e) { return err(e); }
  }
);

// ── Findings ─────────────────────────────────────────────────────────────────

server.tool(
  "create_finding",
  "Create a new security finding in GazeSec.",
  {
    title: z.string().describe("Finding title"),
    description: z.string().describe("Detailed description of the finding"),
    severity: z.enum(["critical", "high", "medium", "low", "informational"])
      .describe("Finding severity"),
    assessment_id: z.string().optional().describe("Assessment UUID to link to"),
    affected_url: z.string().optional().describe("Affected URL"),
    affected_component: z.string().optional().describe("Affected component"),
    affected_parameter: z.string().optional().describe("Affected parameter"),
    cvss_score: z.number().min(0).max(10).optional().describe("CVSS score 0-10"),
    cvss_vector: z.string().optional().describe("CVSS vector string"),
    cwe_id: z.string().optional().describe("CWE ID e.g. CWE-79"),
    cve_id: z.string().optional().describe("CVE ID e.g. CVE-2023-1234"),
    owasp_category: z.string().optional().describe("OWASP category e.g. A01:2021"),
    impact: z.string().optional().describe("Impact description"),
    recommendation: z.string().optional().describe("Remediation recommendation"),
    steps_to_reproduce: z.string().optional().describe("Steps to reproduce"),
    poc_code: z.string().optional().describe("Proof of concept code"),
  },
  async (params) => {
    try {
      const data = await apiRequest("POST", "/api/findings/new", params);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "update_finding",
  "Update an existing finding.",
  {
    finding_id: z.string().describe("Finding UUID"),
    title: z.string().optional(),
    description: z.string().optional(),
    severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(),
    impact: z.string().optional(),
    recommendation: z.string().optional(),
    affected_url: z.string().optional(),
    affected_component: z.string().optional(),
    cvss_score: z.number().min(0).max(10).optional(),
    cvss_vector: z.string().optional(),
    cwe_id: z.string().optional(),
    cve_id: z.string().optional(),
    owasp_category: z.string().optional(),
    steps_to_reproduce: z.string().optional(),
    poc_code: z.string().optional(),
    remediation_notes: z.string().optional(),
  },
  async ({ finding_id, ...updates }) => {
    try {
      const data = await apiRequest("PUT", `/api/findings/${finding_id}`, updates);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "verify_finding",
  "Mark a finding as verified after remediation check.",
  { finding_id: z.string().describe("Finding UUID") },
  async ({ finding_id }) => {
    try {
      const data = await apiRequest("POST", `/api/findings/${finding_id}/verify`);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "update_finding_status",
  "Update the status of a finding.",
  {
    finding_id: z.string().describe("Finding UUID"),
    status: z.enum([
      "open",
      "in_progress",
      "remediated",
      "accepted",
      "false_positive",
      "duplicate",
    ]).describe("New status"),
  },
  async ({ finding_id, status }) => {
    try {
      const data = await apiRequest("POST", `/api/findings/${finding_id}/status`, { status });
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "add_evidence",
  "Add evidence to a finding.",
  {
    finding_id: z.string().describe("Finding UUID"),
    description: z.string().describe("Evidence description"),
    content: z.string().optional().describe("Evidence content or notes"),
  },
  async ({ finding_id, description, content }) => {
    try {
      const data = await apiRequest("POST", `/api/findings/${finding_id}/evidence`, {
        description,
        content,
      });
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_finding",
  "Get full details of a finding including evidence and PoC.",
  { finding_id: z.string().describe("Finding UUID") },
  async ({ finding_id }) => {
    try {
      const data = await apiRequest("GET", `/api/findings/${finding_id}`);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "list_findings",
  "List findings, optionally filtered by assessment.",
  {
    assessment_id: z.string().optional().describe("Filter by assessment UUID"),
  },
  async ({ assessment_id }) => {
    try {
      const path = assessment_id
        ? `/api/assessments/${assessment_id}/findings`
        : "/api/findings/";
      const data = await apiRequest("GET", path);
      return ok(data);
    } catch (e) { return err(e); }
  }
);

// ── Reports ───────────────────────────────────────────────────────────────────

server.tool(
  "generate_report",
  "Generate a report for an assessment. Returns a report URL the user can open.",
  {
    assessment_id: z.string().describe("Assessment UUID"),
    format: z.enum(["pdf", "word", "excel"]).default("pdf").describe("Report format"),
  },
  async ({ assessment_id, format }) => {
    try {
      const data = await apiRequest("POST", "/api/reports/generate", {
        assessment_id,
        format,
      }) as { id?: string };

      const reportId = data?.id;
      if (!reportId) return ok(data);

      return ok({
        ...data,
        report_url: `${API_BASE}/api/reports/${reportId}/view`,
      });
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_report",
  "Get report status and view URL.",
  { report_id: z.string().describe("Report UUID") },
  async ({ report_id }) => {
    try {
      const data = await apiRequest("GET", `/api/reports/${report_id}`) as Record<string, unknown>;
      return ok({
        ...data,
        report_url: `${API_BASE}/api/reports/${report_id}/view`,
      });
    } catch (e) { return err(e); }
  }
);

// ── Assets ────────────────────────────────────────────────────────────────────

server.tool(
  "list_assets",
  "List all assets in GazeSec.",
  {},
  async () => {
    try {
      const data = await apiRequest("GET", "/api/assets");
      return ok(data);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "create_asset",
  "Create a new asset in GazeSec.",
  {
    name: z.string().describe("Asset name"),
    asset_type: z.string().optional().describe("Asset type e.g. web_application, api, mobile"),
    url: z.string().optional().describe("Asset URL"),
    description: z.string().optional().describe("Asset description"),
  },
  async ({ name, asset_type, url, description }) => {
    try {
      const data = await apiRequest("POST", "/api/assets/new", {
        name,
        asset_type,
        url,
        description,
      });
      return ok(data);
    } catch (e) { return err(e); }
  }
);

// ── Transport ─────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("[GazeSec MCP] Server running");
