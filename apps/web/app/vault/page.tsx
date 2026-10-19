"use client";

import { useCallback, useEffect, useState } from "react";
import { Database, Eye, EyeOff, KeyRound, Lock } from "lucide-react";
import {
  ApiError,
  api,
  type ConfigStatus,
  type RestoreResponse,
  type VaultRecord,
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

export default function VaultPage() {
  const [records, setRecords] = useState<VaultRecord[] | null>(null);
  const [status, setStatus] = useState<ConfigStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [recordId, setRecordId] = useState("");
  const [placeholders, setPlaceholders] = useState("");
  const [token, setToken] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [restored, setRestored] = useState<RestoreResponse | null>(null);
  const [restoreError, setRestoreError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([api.vaultRecords(), api.configStatus()])
      .then(([list, cfg]) => {
        if (!cancelled) {
          setRecords(list);
          setStatus(cfg);
        }
      })
      .catch((exc: unknown) => {
        if (!cancelled) {
          setError(exc instanceof ApiError ? exc.message : "Failed to load the vault.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const runRestore = useCallback(async () => {
    setBusy(true);
    setRestoreError(null);
    setRestored(null);
    try {
      const list = placeholders
        .split(/[\n,]+/)
        .map((value) => value.trim())
        .filter(Boolean);
      setRestored(await api.restore(recordId, list, token));
    } catch (exc) {
      setRestoreError(
        exc instanceof ApiError ? exc.message : "Restore failed.",
      );
    } finally {
      setBusy(false);
    }
  }, [recordId, placeholders, token]);

  return (
    <>
      <PageHeader
        title="Vault"
        subtitle="AES-256-GCM encrypted placeholder mappings. The vault key never leaves the backend."
        actions={
          <Badge tone="ok" icon={<Lock className="h-3.5 w-3.5" aria-hidden />}>
            encrypted at rest
          </Badge>
        }
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <Card
          title="Records"
          icon={<Database className="h-4 w-4 text-emerald-400" aria-hidden />}
          className="lg:col-span-2"
        >
          {error && <ErrorBox message={error} />}
          {!records && !error && <Loading label="Loading vault records…" />}
          {records && records.length === 0 && (
            <EmptyBox message="No vault records yet. Analyze an incident to seal its token mapping." />
          )}
          {records && records.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="text-xs uppercase text-zinc-500">
                  <tr>
                    <th className="py-1 pr-3">Record ID</th>
                    <th className="py-1 pr-3">Category</th>
                    <th className="py-1 pr-3">Created</th>
                    <th className="py-1 pr-3">Entries</th>
                    <th className="py-1">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {records.map((record) => (
                    <tr key={record.record_id}>
                      <td className="py-1.5 pr-3 font-mono text-xs text-zinc-300">
                        {record.record_id}
                      </td>
                      <td className="py-1.5 pr-3 text-zinc-400">{record.category}</td>
                      <td className="py-1.5 pr-3 text-zinc-400">
                        {new Date(record.created_at).toLocaleString()}
                      </td>
                      <td className="py-1.5 pr-3 text-zinc-400">{record.entry_count}</td>
                      <td className="py-1.5">
                        <Badge tone={record.encrypted ? "ok" : "danger"}>
                          {record.encrypted ? "encrypted" : "plaintext!"}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className="mt-3 text-xs text-zinc-500">
            Ciphertext only: record listings expose metadata, never plaintext values or
            key material.
          </p>
        </Card>

        <Card
          title="Restore selected placeholders"
          icon={<Eye className="h-4 w-4 text-amber-400" aria-hidden />}
        >
          {!status?.restore_enabled ? (
            <EmptyBox message="Restore is disabled on this instance (no VAULT_RESTORE_TOKEN configured). Enable it deliberately to allow rehydration." />
          ) : (
            <div className="space-y-3">
              <div>
                <label htmlFor="record" className="mb-1 block text-xs text-zinc-500">
                  Record ID
                </label>
                <input
                  id="record"
                  list="record-ids"
                  value={recordId}
                  onChange={(e) => setRecordId(e.target.value)}
                  className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-200"
                  placeholder="req_…"
                />
                <datalist id="record-ids">
                  {(records ?? []).map((record) => (
                    <option key={record.record_id} value={record.record_id} />
                  ))}
                </datalist>
              </div>

              <div>
                <label htmlFor="placeholders" className="mb-1 block text-xs text-zinc-500">
                  Placeholders (one per line)
                </label>
                <textarea
                  id="placeholders"
                  value={placeholders}
                  onChange={(e) => setPlaceholders(e.target.value)}
                  rows={3}
                  className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-200"
                  placeholder={"[SECRET_01]\n[EMAIL_01]"}
                />
              </div>

              <div>
                <label htmlFor="token" className="mb-1 block text-xs text-zinc-500">
                  Restore authorization token
                </label>
                <input
                  id="token"
                  type="password"
                  autoComplete="off"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 font-mono text-sm text-zinc-200"
                  placeholder="••••••••"
                />
              </div>

              <label className="flex items-start gap-2 text-xs text-zinc-400">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(e) => setConfirmed(e.target.checked)}
                  className="mt-0.5"
                />
                I understand restored values are revealed to this browser session and
                the action is audited.
              </label>

              <Button
                onClick={runRestore}
                loading={busy}
                disabled={!recordId || !placeholders || !token || !confirmed}
                variant="danger"
              >
                <KeyRound className="h-4 w-4" aria-hidden />
                Reveal values
              </Button>
            </div>
          )}

          {restoreError && (
            <div className="mt-3">
              <ErrorBox message={restoreError} />
            </div>
          )}

          {restored && (
            <div className="mt-3 space-y-2">
              <Badge tone="warn" icon={<EyeOff className="h-3.5 w-3.5" aria-hidden />}>
                restored — handled as plaintext
              </Badge>
              <dl className="space-y-1.5">
                {Object.entries(restored.values).map(([placeholder, value]) => (
                  <div
                    key={placeholder}
                    className="rounded-md border border-zinc-800 bg-zinc-950/70 px-3 py-2"
                  >
                    <dt className="font-mono text-xs text-emerald-300">{placeholder}</dt>
                    <dd className="font-mono break-all text-sm text-amber-100">{value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
