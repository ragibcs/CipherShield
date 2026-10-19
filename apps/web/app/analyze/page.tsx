"use client";

import { useCallback, useEffect, useState } from "react";
import {
  EyeOff,
  FileSearch,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import {
  ApiError,
  api,
  type AnalyzeResponse,
  type ConfigStatus,
  type PreviewResponse,
} from "@/lib/api";
import { SAMPLE_CLEAN, SAMPLE_INCIDENT, SAMPLE_INJECTION } from "@/lib/samples";
import {
  Badge,
  Button,
  Card,
  ErrorBox,
  Loading,
  PageHeader,
} from "@/components/ui";

const CATEGORY_TONE: Record<string, string> = {
  api_token: "border-red-500/40 text-red-300",
  bearer_token: "border-red-500/40 text-red-300",
  password_kv: "border-amber-500/40 text-amber-300",
  email: "border-sky-500/40 text-sky-300",
  ipv4: "border-zinc-600 text-zinc-300",
};

export default function AnalyzePage() {
  const [text, setText] = useState(SAMPLE_INCIDENT);
  const [status, setStatus] = useState<ConfigStatus | null>(null);
  const [preview, setPreview] = useState<PreviewResponse | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);
  const [busy, setBusy] = useState<"preview" | "analyze" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .configStatus()
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  const runPreview = useCallback(async () => {
    setBusy("preview");
    setError(null);
    setResult(null);
    try {
      setPreview(await api.preview(text));
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Preview failed.");
    } finally {
      setBusy(null);
    }
  }, [text]);

  const runAnalyze = useCallback(async () => {
    setBusy("analyze");
    setError(null);
    try {
      setResult(await api.analyze(text));
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Analysis failed.");
    } finally {
      setBusy(null);
    }
  }, [text]);

  return (
    <>
      <PageHeader
        title="Analyze"
        subtitle="Review redactions, inspect the outbound payload, then analyze securely."
        actions={
          <Badge tone="info" icon={<EyeOff className="h-3.5 w-3.5" aria-hidden />}>
            {status
              ? status.external_calls_enabled
                ? "external: enabled"
                : "external: disabled (mock)"
              : "status…"}
          </Badge>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card
          title="Incident input"
          icon={<FileSearch className="h-4 w-4 text-emerald-400" aria-hidden />}
          actions={
            <div className="flex gap-1.5">
              <Button variant="ghost" onClick={() => setText(SAMPLE_INCIDENT)}>
                Incident
              </Button>
              <Button variant="ghost" onClick={() => setText(SAMPLE_CLEAN)}>
                Clean
              </Button>
              <Button variant="ghost" onClick={() => setText(SAMPLE_INJECTION)}>
                Injection
              </Button>
            </div>
          }
        >
          <label htmlFor="incident" className="sr-only">
            Incident report text
          </label>
          <textarea
            id="incident"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={14}
            spellCheck={false}
            className="w-full resize-y rounded-lg border border-zinc-800 bg-zinc-950 p-3 font-mono text-sm text-zinc-200 placeholder:text-zinc-600"
            placeholder="Paste a synthetic incident report or log excerpt…"
          />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button onClick={runPreview} loading={busy === "preview"}>
              Preview redaction
            </Button>
            <Button onClick={runAnalyze} loading={busy === "analyze"}>
              <ShieldCheck className="h-4 w-4" aria-hidden />
              Analyze securely
            </Button>
            <span className="text-xs text-zinc-500">{text.length} chars</span>
          </div>
          <p className="mt-3 flex items-start gap-1.5 text-xs text-zinc-500">
            <Send className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-600" aria-hidden />
            {status?.external_calls_enabled
              ? "External disclosure: the sanitized payload (placeholders only) will be sent to the configured provider."
              : "External disclosure: external calls are disabled — analysis runs on the deterministic mock provider. Nothing leaves this machine."}
          </p>
        </Card>

        <Card
          title="Redaction preview"
          icon={<EyeOff className="h-4 w-4 text-sky-400" aria-hidden />}
        >
          {error && <ErrorBox message={error} />}
          {!error && busy === "preview" && <Loading label="Scanning for sensitive values…" />}
          {!error && !preview && busy !== "preview" && (
            <p className="text-sm text-zinc-500">
              Run a preview to see detected categories, proposed placeholders, and the
              sanitized text that would be sent to the model.
            </p>
          )}
          {preview && (
            <div className="space-y-4">
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(preview.counts).length === 0 && (
                  <Badge tone="neutral">no sensitive values detected</Badge>
                )}
                {Object.entries(preview.counts).map(([category, count]) => (
                  <span
                    key={category}
                    className={`rounded-full border px-2.5 py-0.5 text-xs ${CATEGORY_TONE[category] ?? "border-zinc-700 text-zinc-300"}`}
                  >
                    {category}: {count}
                  </span>
                ))}
              </div>

              {preview.findings.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="text-xs uppercase text-zinc-500">
                      <tr>
                        <th className="py-1 pr-3">Category</th>
                        <th className="py-1 pr-3">Detected value</th>
                        <th className="py-1 pr-3">Placeholder</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-800">
                      {preview.findings.map((finding) => (
                        <tr key={`${finding.start}-${finding.end}`}>
                          <td className="py-1.5 pr-3 text-zinc-400">{finding.category}</td>
                          <td className="py-1.5 pr-3 font-mono text-amber-200/90">
                            {finding.value.length > 42
                              ? `${finding.value.slice(0, 42)}…`
                              : finding.value}
                          </td>
                          <td className="py-1.5 pr-3 font-mono text-emerald-300">
                            {finding.placeholder}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-zinc-500">Nothing to redact.</p>
              )}

              <div>
                <h3 className="mb-1 text-xs uppercase tracking-wide text-zinc-500">
                  Sanitized outbound text
                </h3>
                <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs leading-relaxed text-emerald-100">
                  {preview.sanitized_text}
                </pre>
              </div>
              <p className="text-xs text-zinc-500">{preview.detector_coverage_note}</p>
            </div>
          )}
        </Card>
      </div>

      {result && (
        <div className="mt-4">
          {result.status === "blocked" ? (
            <Card
              title="Request blocked by policy"
              icon={<ShieldAlert className="h-4 w-4 text-red-400" aria-hidden />}
            >
              <ErrorBox
                message={`${result.policy.reason} (code: ${result.policy.code})`}
              />
              <p className="mt-2 text-sm text-zinc-400">
                No provider request was made — the provider call counter remains at{" "}
                <span className="font-mono">{result.provider_calls}</span>.
              </p>
            </Card>
          ) : (
            <Card
              title="Analysis result"
              icon={<Sparkles className="h-4 w-4 text-emerald-400" aria-hidden />}
              actions={
                <div className="flex flex-wrap gap-1.5">
                  <Badge tone="ok">{result.policy.code}</Badge>
                  <Badge tone="neutral">{result.provider}</Badge>
                  {result.response_inspection && (
                    <Badge tone={result.response_inspection.leak_detected ? "warn" : "ok"}>
                      inspection: {result.response_inspection.action}
                    </Badge>
                  )}
                </div>
              }
            >
              <div className="grid gap-4 lg:grid-cols-2">
                <div>
                  <h3 className="mb-1 text-xs uppercase tracking-wide text-zinc-500">
                    Sanitized model output
                  </h3>
                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs leading-relaxed text-zinc-200">
                    {result.output}
                  </pre>
                </div>
                <div className="space-y-3 text-sm">
                  <dl className="grid grid-cols-2 gap-2">
                    <div className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                      <dt className="text-xs text-zinc-500">Request ID</dt>
                      <dd className="truncate font-mono text-zinc-200">
                        {result.request_id}
                      </dd>
                    </div>
                    <div className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                      <dt className="text-xs text-zinc-500">Latency</dt>
                      <dd className="font-mono text-zinc-200">
                        {result.latency_ms != null
                          ? `${result.latency_ms.toFixed(1)} ms`
                          : "—"}
                      </dd>
                    </div>
                    <div className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                      <dt className="text-xs text-zinc-500">Model</dt>
                      <dd className="truncate font-mono text-zinc-200">
                        {result.model ?? "—"}
                      </dd>
                    </div>
                    <div className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                      <dt className="text-xs text-zinc-500">Provider calls</dt>
                      <dd className="font-mono text-zinc-200">{result.provider_calls}</dd>
                    </div>
                  </dl>

                  <details className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3">
                    <summary className="text-sm font-medium text-zinc-300">
                      Exact outbound payload (proves placeholders only)
                    </summary>
                    <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap text-xs text-emerald-100">
                      {result.outbound_body}
                    </pre>
                  </details>
                </div>
              </div>
            </Card>
          )}
        </div>
      )}
    </>
  );
}
