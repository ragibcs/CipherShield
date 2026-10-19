/** Typed API client for the CipherShield backend. */

/**
 * API base URL. Empty string = same origin: the Next server proxies
 * `/api/*` and `/health` to the backend (see next.config.ts rewrites),
 * which is what single-port deployments and the all-in-one container use.
 * Cross-origin deployments set NEXT_PUBLIC_API_URL to the public API origin.
 */
export const API_BASE = (process.env.NEXT_PUBLIC_API_URL ?? "").replace(
  /\/+$/,
  "",
);

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function request<T>(
  path: string,
  init?: RequestInit,
  timeoutMs = 20000,
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init?.headers ?? {}),
      },
      signal: controller.signal,
    });
  } catch {
    throw new ApiError(
      "network_error",
      "Could not reach the CipherShield backend. Is it running?",
      0,
    );
  } finally {
    clearTimeout(timer);
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const error = (payload as { error?: { code?: string; message?: string } })
      ?.error;
    throw new ApiError(
      error?.code ?? "http_error",
      error?.message ?? `Request failed with status ${response.status}.`,
      response.status,
    );
  }
  return payload as T;
}

/* ----------------------------- wire types ------------------------------ */

export type ConfigStatus = {
  app_env: string;
  version: string;
  provider: string;
  external_enabled: boolean;
  provider_configured: boolean;
  external_calls_enabled: boolean;
  restore_enabled: boolean;
  detector_categories: string[];
  max_input_chars: number;
  max_output_tokens: number;
};

export type PreviewFinding = {
  category: string;
  placeholder: string;
  value: string;
  start: number;
  end: number;
};

export type PreviewResponse = {
  request_id: string;
  counts: Record<string, number>;
  findings: PreviewFinding[];
  sanitized_text: string;
  detector_coverage_note: string;
};

export type PolicyInfo = { allowed: boolean; code: string; reason: string };

export type ResponseInspection = {
  action: "allow" | "mask" | "block";
  masked_count: number;
  leak_detected: boolean;
  counts: Record<string, number>;
};

export type AnalyzeResponse = {
  status: "completed" | "blocked";
  request_id: string;
  counts: Record<string, number>;
  sanitized_text: string;
  policy: PolicyInfo;
  provider: string | null;
  model: string | null;
  latency_ms: number | null;
  output: string | null;
  response_inspection: ResponseInspection | null;
  outbound_body: string | null;
  provider_calls: number;
};

export type AuditEvent = {
  id: number;
  request_id: string;
  timestamp: string;
  event_type: string;
  decision: string;
  reason_code: string;
  categories: Record<string, number>;
  provider: string;
  model: string;
  latency_ms: number | null;
  outcome: string;
  event_hash: string;
};

export type AuditList = { events: AuditEvent[]; chain_valid: boolean };

export type VaultRecord = {
  record_id: string;
  category: string;
  created_at: string;
  entry_count: number;
  encrypted: boolean;
};

export type RestoreResponse = { record_id: string; values: Record<string, string> };

export type EvaluationSummary = {
  status: "ready" | "not_generated";
  generated_at: string | null;
  source: string | null;
  metrics: Record<string, number | Record<string, number>>;
  note: string;
};

export type ScenarioMeta = {
  id: string;
  title: string;
  description: string;
  expected: string;
  abuse_case: string;
};

export type ScenarioRun = {
  scenario_id: string;
  title: string;
  expected: string;
  actual: string;
  passed: boolean;
  evidence: Record<string, unknown>;
  ran_at: string;
};

/* -------------------------------- calls -------------------------------- */

export const api = {
  configStatus: () => request<ConfigStatus>("/api/v1/config/status"),
  preview: (text: string) =>
    request<PreviewResponse>("/api/v1/analyze/preview", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  analyze: (text: string) =>
    request<AnalyzeResponse>("/api/v1/analyze", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  audit: (limit = 50) => request<AuditList>(`/api/v1/audit?limit=${limit}`),
  vaultRecords: () => request<VaultRecord[]>("/api/v1/vault/records"),
  restore: (record_id: string, placeholders: string[], token: string) =>
    request<RestoreResponse>("/api/v1/vault/restore", {
      method: "POST",
      body: JSON.stringify({ record_id, placeholders, token }),
    }),
  evaluationSummary: () => request<EvaluationSummary>("/api/v1/evaluation/summary"),
  labScenarios: () => request<{ scenarios: ScenarioMeta[] }>("/api/v1/lab/scenarios"),
  runScenario: (scenario_id: string) =>
    request<ScenarioRun>("/api/v1/lab/run", {
      method: "POST",
      body: JSON.stringify({ scenario_id }),
    }),
};
