"use client";

import { useCallback, useEffect, useState } from "react";
import { CheckCircle2, Download, ScrollText, XCircle } from "lucide-react";
import {
  ApiError,
  api,
  type AuditList,
  type EvaluationSummary,
} from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  EmptyBox,
  ErrorBox,
  Loading,
  PageHeader,
} from "@/components/ui";

const DECISION_TONE: Record<string, "ok" | "warn" | "danger" | "neutral"> = {
  allowed: "ok",
  passed: "ok",
  blocked: "danger",
  failed: "danger",
  denied: "warn",
  error: "warn",
};

function formatMetricValue(value: number | Record<string, number>): string {
  if (typeof value === "number") {
    return Number.isInteger(value) ? String(value) : value.toFixed(4);
  }
  return Object.entries(value)
    .map(([k, v]) => `${k}: ${typeof v === "number" ? v.toFixed(4) : v}`)
    .join(", ");
}

export default function AuditPage() {
  const [audit, setAudit] = useState<AuditList | null>(null);
  const [evaluation, setEvaluation] = useState<EvaluationSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exported, setExported] = useState(false);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.audit(100), api.evaluationSummary()])
      .then(([events, summary]) => {
        if (!cancelled) {
          setAudit(events);
          setEvaluation(summary);
        }
      })
      .catch((exc: unknown) => {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Failed to load audit data.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const exportReport = useCallback(() => {
    if (!audit || !evaluation) return;
    const report = {
      exported_at: new Date().toISOString(),
      note: "Sanitized report: audit events and measured metrics only — no raw prompts, outputs, secrets, or keys.",
      audit_chain_valid: audit.chain_valid,
      audit_events: audit.events,
      evaluation,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "ciphershield-report.json";
    anchor.click();
    URL.revokeObjectURL(url);
    setExported(true);
  }, [audit, evaluation]);

  if (error) {
    return (
      <>
        <PageHeader title="Audit & Evaluation" />
        <ErrorBox message={error} />
      </>
    );
  }
  if (!audit || !evaluation) {
    return (
      <>
        <PageHeader title="Audit & Evaluation" />
        <Loading label="Loading audit trail…" />
      </>
    );
  }

  const evalReady = evaluation.status === "ready";

  return (
    <>
      <PageHeader
        title="Audit & Evaluation"
        subtitle="Secret-free timeline and metrics produced by real test runs."
        actions={
          <Button
            variant="ghost"
            onClick={exportReport}
            disabled={audit.events.length === 0}
          >
            <Download className="h-4 w-4" aria-hidden />
            Export sanitized report
          </Button>
        }
      />

      {exported && (
        <div className="mb-4">
          <Badge tone="ok" icon={<CheckCircle2 className="h-3.5 w-3.5" aria-hidden />}>
            report downloaded (contains no raw secrets)
          </Badge>
        </div>
      )}

      <Card
        title="Evaluation metrics"
        actions={
          evalReady ? (
            <Badge tone="ok">measured · {evaluation.generated_at ?? "unknown"}</Badge>
          ) : (
            <Badge tone="warn">not yet verified</Badge>
          )
        }
      >
        {evalReady ? (
          <div className="space-y-3">
            <p className="text-xs text-zinc-500">
              Source: {evaluation.source ?? "unknown"} — every number below was written
              by the evaluation runner.
            </p>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {Object.entries(evaluation.metrics).map(([key, value]) => (
                <div
                  key={key}
                  className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3"
                >
                  <p className="text-xs capitalize text-zinc-500">
                    {key.replace(/_/g, " ")}
                  </p>
                  <p className="mt-1 text-lg font-semibold text-zinc-100">
                    {formatMetricValue(value)}
                  </p>
                </div>
              ))}
            </div>
            <p className="text-xs text-zinc-500">{evaluation.note}</p>
          </div>
        ) : (
          <EmptyBox message="No evaluation run yet. Execute `python scripts/run_security_eval.py` — the dashboard renders its recorded output and never invents numbers." />
        )}
      </Card>

      <Card
        className="mt-4"
        title="Audit trail"
        icon={<ScrollText className="h-4 w-4 text-zinc-400" aria-hidden />}
        actions={
          <Badge
            tone={audit.chain_valid ? "ok" : "danger"}
            icon={
              audit.chain_valid ? (
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <XCircle className="h-3.5 w-3.5" aria-hidden />
              )
            }
          >
            hash chain {audit.chain_valid ? "verified" : "broken"}
          </Badge>
        }
      >
        {audit.events.length === 0 ? (
          <EmptyBox message="No audit events recorded yet." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-zinc-500">
                <tr>
                  <th className="py-1 pr-3">Time</th>
                  <th className="py-1 pr-3">Event</th>
                  <th className="py-1 pr-3">Decision</th>
                  <th className="py-1 pr-3">Reason</th>
                  <th className="py-1 pr-3">Categories</th>
                  <th className="py-1 pr-3">Provider</th>
                  <th className="py-1">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {audit.events.map((event) => (
                  <tr key={event.id}>
                    <td className="py-1.5 pr-3 text-xs text-zinc-500">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-1.5 pr-3 text-zinc-300">{event.event_type}</td>
                    <td className="py-1.5 pr-3">
                      <Badge tone={DECISION_TONE[event.decision] ?? "neutral"}>
                        {event.decision}
                      </Badge>
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs text-zinc-400">
                      {event.reason_code}
                    </td>
                    <td className="py-1.5 pr-3 text-xs text-zinc-400">
                      {Object.entries(event.categories)
                        .map(([k, v]) => `${k}:${v}`)
                        .join(" ") || "—"}
                    </td>
                    <td className="py-1.5 pr-3 text-xs text-zinc-400">
                      {event.provider}
                      {event.model ? ` / ${event.model}` : ""}
                    </td>
                    <td className="py-1.5 text-xs text-zinc-400">
                      {event.latency_ms != null
                        ? `${event.latency_ms.toFixed(1)} ms`
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="mt-3 text-xs text-zinc-500">
          Events store metadata only: no raw prompts, model outputs, secrets, keys, or
          vault mappings — enforced by fixed-field schema and tests.
        </p>
      </Card>
    </>
  );
}
