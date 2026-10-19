"use client";

import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Database,
  EyeOff,
  FileSearch,
  Radio,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import {
  ApiError,
  api,
  type AuditList,
  type ConfigStatus,
  type EvaluationSummary,
  type VaultRecord,
} from "@/lib/api";
import { Badge, Card, EmptyBox, ErrorBox, Loading, PageHeader, StatCard } from "@/components/ui";

type OverviewData = {
  status: ConfigStatus;
  audit: AuditList;
  evaluation: EvaluationSummary;
  records: VaultRecord[];
};

const DECISION_TONE = {
  allowed: "ok",
  passed: "ok",
  blocked: "danger",
  failed: "danger",
  denied: "warn",
  error: "warn",
} as const;

export default function OverviewPage() {
  const [data, setData] = useState<OverviewData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      api.configStatus(),
      api.audit(8),
      api.evaluationSummary(),
      api.vaultRecords(),
    ])
      .then(([status, audit, evaluation, records]) => {
        if (!cancelled) setData({ status, audit, evaluation, records });
      })
      .catch((exc: unknown) => {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Unexpected error.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <>
        <PageHeader title="Overview" subtitle="Gateway security posture" />
        <ErrorBox message={error} />
      </>
    );
  }
  if (!data) {
    return (
      <>
        <PageHeader title="Overview" subtitle="Gateway security posture" />
        <Loading label="Loading security status…" />
      </>
    );
  }

  const { status, audit, evaluation, records } = data;
  const blocked = audit.events.filter((e) => e.decision === "blocked").length;
  const detected = audit.events.reduce(
    (sum, event) =>
      sum + Object.values(event.categories).reduce((a, b) => a + b, 0),
    0,
  );
  const evalReady = evaluation.status === "ready";

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle="Local-first secret-isolating gateway — status comes from live backend state."
        actions={
          <Badge
            tone={status.external_calls_enabled ? "warn" : "ok"}
            icon={
              status.external_calls_enabled ? (
                <Radio className="h-3.5 w-3.5" aria-hidden />
              ) : (
                <EyeOff className="h-3.5 w-3.5" aria-hidden />
              )
            }
          >
            {status.external_calls_enabled
              ? "External calls enabled"
              : "External calls disabled"}
          </Badge>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Provider mode"
          icon={<Radio className="h-3.5 w-3.5" aria-hidden />}
          value={status.provider === "mock" ? "Mock (offline)" : "HTTP adapter"}
          hint={
            status.external_calls_enabled
              ? "Sanitized prompts may leave this machine."
              : "No prompt leaves this machine by default."
          }
          badge={
            <Badge tone={status.provider === "mock" ? "ok" : "warn"}>
              {status.provider}
            </Badge>
          }
        />
        <StatCard
          label="Vault records"
          icon={<Database className="h-3.5 w-3.5" aria-hidden />}
          value={records.length}
          hint="AES-256-GCM encrypted mappings, key stays backend-side."
        />
        <StatCard
          label="Blocked attempts (recent)"
          icon={<ShieldAlert className="h-3.5 w-3.5" aria-hidden />}
          value={blocked}
          hint={`Across the last ${audit.events.length} audit events.`}
        />
        <StatCard
          label="Detected secrets (recent)"
          icon={<FileSearch className="h-3.5 w-3.5" aria-hidden />}
          value={detected}
          hint="Detector hits in recent audited requests."
        />
      </div>

      <div className="mt-6 grid gap-4 lg:grid-cols-3">
        <Card title="Security controls" icon={<ShieldCheck className="h-4 w-4 text-emerald-400" aria-hidden />}>
          <ul className="space-y-3 text-sm">
            <li className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">External LLM opt-in</span>
              <Badge tone={status.external_enabled ? "warn" : "ok"}>
                {status.external_enabled ? "enabled by config" : "disabled (default)"}
              </Badge>
            </li>
            <li className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">Provider configuration</span>
              <Badge tone={status.provider_configured ? "ok" : "neutral"}>
                {status.provider_configured ? "configured" : "not configured"}
              </Badge>
            </li>
            <li className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">Vault restore</span>
              <Badge tone={status.restore_enabled ? "warn" : "ok"}>
                {status.restore_enabled ? "authorized mode" : "disabled (default)"}
              </Badge>
            </li>
            <li className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">Audit hash chain</span>
              <Badge
                tone={audit.chain_valid ? "ok" : "danger"}
                icon={
                  audit.chain_valid ? (
                    <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                  ) : undefined
                }
              >
                {audit.chain_valid ? "verified" : "broken"}
              </Badge>
            </li>
            <li className="flex items-center justify-between gap-2">
              <span className="text-zinc-400">Detector coverage</span>
              <Badge tone="info">{status.detector_categories.length} categories</Badge>
            </li>
          </ul>
          <p className="mt-3 text-xs text-zinc-500">
            Detected categories: {status.detector_categories.join(", ")}.
          </p>
        </Card>

        <Card
          title="Evaluation metrics"
          icon={<ScrollText className="h-4 w-4 text-sky-400" aria-hidden />}
          actions={
            evalReady ? (
              <Badge tone="ok">measured</Badge>
            ) : (
              <Badge tone="warn">not yet verified</Badge>
            )
          }
        >
          {evalReady ? (
            <div className="space-y-3">
              <p className="text-xs text-zinc-500">
                Generated {evaluation.generated_at ?? "unknown"} · {evaluation.source ?? "unknown source"}
              </p>
              <dl className="grid grid-cols-2 gap-2 text-sm">
                {Object.entries(evaluation.metrics)
                  .slice(0, 8)
                  .map(([key, value]) => (
                    <div
                      key={key}
                      className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2"
                    >
                      <dt className="text-xs capitalize text-zinc-500">
                        {key.replace(/_/g, " ")}
                      </dt>
                      <dd className="font-medium text-zinc-100">
                        {typeof value === "number"
                          ? Number.isInteger(value)
                            ? value
                            : value.toFixed(4)
                          : JSON.stringify(value)}
                      </dd>
                    </div>
                  ))}
              </dl>
              <p className="text-xs text-zinc-500">{evaluation.note}</p>
            </div>
          ) : (
            <EmptyBox message="No evaluation run yet. Metrics appear only after `scripts/run_security_eval.py` records real results — never hardcoded." />
          )}
        </Card>

        <Card title="Recent activity" icon={<ScrollText className="h-4 w-4 text-zinc-400" aria-hidden />}>
          {audit.events.length === 0 ? (
            <EmptyBox message="No audit events yet. Preview or analyze an incident to get started." />
          ) : (
            <ul className="space-y-2 text-sm">
              {audit.events.slice(0, 6).map((event) => (
                <li
                  key={event.id}
                  className="flex items-center justify-between gap-2 rounded-md border border-zinc-800 bg-zinc-950/50 px-3 py-2"
                >
                  <span className="truncate text-zinc-300">
                    {event.event_type}
                    <span className="text-zinc-600"> · {event.reason_code}</span>
                  </span>
                  <Badge
                    tone={
                      DECISION_TONE[event.decision as keyof typeof DECISION_TONE] ??
                      "neutral"
                    }
                  >
                    {event.decision}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
