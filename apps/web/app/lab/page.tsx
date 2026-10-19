"use client";

import { useCallback, useEffect, useState } from "react";
import { FlaskConical, Play, ShieldX } from "lucide-react";
import { ApiError, api, type ScenarioMeta, type ScenarioRun } from "@/lib/api";
import {
  Badge,
  Button,
  Card,
  EmptyBox,
  ErrorBox,
  Loading,
  PageHeader,
} from "@/components/ui";

export default function LabPage() {
  const [scenarios, setScenarios] = useState<ScenarioMeta[] | null>(null);
  const [results, setResults] = useState<Record<string, ScenarioRun>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .labScenarios()
      .then((data) => setScenarios(data.scenarios))
      .catch((exc) =>
        setError(exc instanceof ApiError ? exc.message : "Failed to load scenarios."),
      );
  }, []);

  const runOne = useCallback(async (scenarioId: string) => {
    setRunning(scenarioId);
    setError(null);
    try {
      const result = await api.runScenario(scenarioId);
      setResults((prev) => ({ ...prev, [scenarioId]: result }));
    } catch (exc) {
      setError(exc instanceof ApiError ? exc.message : "Scenario failed to run.");
    } finally {
      setRunning(null);
    }
  }, []);

  const runAll = useCallback(async () => {
    if (!scenarios) return;
    setError(null);
    for (const scenario of scenarios) {
      await runOne(scenario.id);
    }
  }, [scenarios, runOne]);

  const passed = Object.values(results).filter((r) => r.passed).length;
  const total = Object.keys(results).length;

  return (
    <>
      <PageHeader
        title="Security Lab"
        subtitle="Attack scenarios executed against the real pipeline — expected vs actual, per abuse case."
        actions={
          <Button onClick={runAll} loading={running !== null} disabled={!scenarios}>
            <Play className="h-4 w-4" aria-hidden />
            Run all scenarios
          </Button>
        }
      />

      {error && <div className="mb-4"><ErrorBox message={error} /></div>}
      {!scenarios && !error && <Loading label="Loading scenarios…" />}
      {scenarios && scenarios.length === 0 && (
        <EmptyBox message="No scenarios defined." />
      )}

      {scenarios && scenarios.length > 0 && (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2 text-sm text-zinc-400">
            <FlaskConical className="h-4 w-4 text-sky-400" aria-hidden />
            {total === 0 ? (
              <span>No scenarios run yet in this session.</span>
            ) : (
              <span>
                <span className="font-medium text-zinc-100">{passed}</span> / {total}{" "}
                passed this session
              </span>
            )}
            <Badge tone="neutral">results are live, not hardcoded</Badge>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            {scenarios.map((scenario) => {
              const result = results[scenario.id];
              return (
                <Card
                  key={scenario.id}
                  title={scenario.title}
                  actions={
                    result ? (
                      <Badge
                        tone={result.passed ? "ok" : "danger"}
                        icon={
                          result.passed ? undefined : (
                            <ShieldX className="h-3.5 w-3.5" aria-hidden />
                          )
                        }
                      >
                        {result.passed ? "PASS" : "FAIL"}
                      </Badge>
                    ) : (
                      <Badge tone="neutral">not run</Badge>
                    )
                  }
                >
                  <div className="space-y-3 text-sm">
                    <p className="text-zinc-400">{scenario.description}</p>
                    <div className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                      <p className="text-xs uppercase tracking-wide text-zinc-500">
                        Expected
                      </p>
                      <p className="text-zinc-300">{scenario.expected}</p>
                    </div>

                    {result && (
                      <>
                        <div
                          className={`rounded-md border px-3 py-2 ${
                            result.passed
                              ? "border-emerald-500/30 bg-emerald-500/5"
                              : "border-red-500/40 bg-red-500/10"
                          }`}
                        >
                          <p className="text-xs uppercase tracking-wide text-zinc-500">
                            Actual
                          </p>
                          <p className="text-zinc-200">{result.actual}</p>
                        </div>
                        <details className="rounded-md border border-zinc-800 bg-zinc-950/60 px-3 py-2">
                          <summary className="text-xs font-medium text-zinc-400">
                            Evidence (sanitized)
                          </summary>
                          <pre className="mt-2 max-h-40 overflow-auto text-xs text-zinc-400">
                            {JSON.stringify(result.evidence, null, 2)}
                          </pre>
                        </details>
                        <p className="text-xs text-zinc-600">Ran at {result.ran_at}</p>
                      </>
                    )}

                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-zinc-600">
                        {scenario.abuse_case} · {scenario.id}
                      </span>
                      <Button
                        variant="ghost"
                        onClick={() => void runOne(scenario.id)}
                        loading={running === scenario.id}
                        disabled={running !== null}
                      >
                        Run scenario
                      </Button>
                    </div>
                  </div>
                </Card>
              );
            })}
          </div>
        </>
      )}
    </>
  );
}
