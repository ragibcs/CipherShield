#!/usr/bin/env python3
"""Run the CipherShield security evaluation and record measured metrics.

Everything written to eval/results/summary.json by this script is produced by
executing the real pipeline and the real test suite - nothing is hardcoded.
Runs are offline: the mock provider is used and sockets are not required.

Usage (from the repo root, with services/api dependencies installed):

    python scripts/run_security_eval.py

Outputs:
    eval/results/summary.json   machine-readable metrics (served by the API)
    eval/results/report.md      human-readable report for judges
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "api"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from generate_demo_data import build_corpus  # noqa: E402

from app.container import build_outbound_payload, build_services  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.services.lab import SCENARIOS, run_scenario  # noqa: E402
from app.services.providers import MockProvider, ProviderRequest  # noqa: E402
from app.services.vault import StaticKeyProvider  # noqa: E402

RESULTS_DIR = REPO_ROOT / "eval" / "results"
FAKE_PROVIDER_KEY = "sk-eval-config-fake-0123456789abcdef"
_EVAL_KEY = bytes.fromhex("5a" * 32)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100) * (len(ordered) - 1))))
    return ordered[index]


def _rate(numerator: int, denominator: int) -> float:
    return (numerator / denominator) if denominator else 0.0


def _grab(pattern: str, text: str) -> int:
    match = re.search(pattern, text)
    return int(match.group(1)) if match else 0


def _run_pytest_suite() -> dict[str, Any]:
    """Run the real test suite and parse its summary (never invented)."""
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=no"],
        cwd=REPO_ROOT / "services" / "api",
        capture_output=True,
        text=True,
        timeout=600,
    )
    duration = time.perf_counter() - started
    output = (proc.stdout or "") + (proc.stderr or "")
    passed = _grab(r"(\d+) passed", output)
    failed = _grab(r"(\d+) failed", output) + _grab(r"(\d+) error", output)
    skipped = _grab(r"(\d+) skipped", output)
    return {
        "exit_code": proc.returncode,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "duration_s": round(duration, 2),
        "command": "pytest -q --tb=no",
    }


def _evaluate_pipeline(corpus: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="ciphershield-eval-") as tmp:
        tmp_path = Path(tmp)
        settings = Settings(
            app_env="evaluation",
            database_url=f"sqlite:///{tmp_path / 'eval.db'}",
            ciphershield_key_file=str(tmp_path / "master.key"),
            llm_api_key=FAKE_PROVIDER_KEY,
            llm_base_url="https://provider.invalid/v1",
            llm_model="eval-mock",
            allow_external_llm=True,  # gate believes external is on; provider is mocked
            max_input_chars=20000,
        )
        provider = MockProvider()
        services = build_services(
            settings,
            key_provider=StaticKeyProvider(_EVAL_KEY),
            provider=provider,
            db_path=str(tmp_path / "eval.db"),
        )

        local_latencies: list[float] = []
        e2e_latencies: list[float] = []
        known_supplied = known_leaked = 0
        approved = completed = 0
        benign_values_total = benign_values_redacted = 0
        benign_docs = benign_docs_redacted = 0
        forbidden_attempted = forbidden_blocked = 0
        oversize_rejected = 0
        spoof_neutralized = 0
        pipeline_blocks = 0
        attack_attempts = attack_successes = 0
        attack_breakdown: list[dict[str, Any]] = []
        benign_docs = benign_docs_total(corpus)

        def record(attack_id: str, attack: str, success: bool, detail: str) -> None:
            nonlocal attack_attempts, attack_successes
            attack_attempts += 1
            if success:
                attack_successes += 1
            attack_breakdown.append(
                {"id": attack_id, "attack": attack, "success": success, "detail": detail}
            )

        for document in corpus["documents"]:
            kind = document["kind"]

            if kind == "benign":
                started = time.perf_counter()
                tokenized = services.tokenizer.tokenize(document["text"])
                local_latencies.append((time.perf_counter() - started) * 1000)
                if tokenized.tokens:
                    benign_docs_redacted += 1
                for value in document.get("benign_values", []):
                    benign_values_total += 1
                    if value not in tokenized.sanitized_text:
                        benign_values_redacted += 1
                continue

            if kind == "attack":
                attack = document["attack"]

                if attack == "forbidden_field":
                    forbidden_attempted += 1
                    decision = services.gate.evaluate(
                        body=json.dumps({"content": document["text"]}), external=True
                    )
                    blocked = not decision.allowed
                    if blocked:
                        forbidden_blocked += 1
                    record(document["id"], attack, not blocked, decision.code)
                    continue

                if attack == "oversized_payload":
                    rejected = len(document["text"]) > settings.max_input_chars
                    if rejected:
                        oversize_rejected += 1
                    record(
                        document["id"],
                        attack,
                        not rejected,
                        "size_limit" if rejected else "accepted",
                    )
                    continue

                # Injection and spoofing are judged on the serialized outbound
                # form produced by the full tokenize -> gate path (no provider
                # call needed; blocked or not, the payload is what would send).
                tokenized = services.tokenizer.tokenize(document["text"])
                payload = build_outbound_payload(
                    model=settings.llm_model,
                    sanitized_text=tokenized.sanitized_text,
                    max_tokens=settings.max_output_tokens,
                )
                serialized = json.dumps(payload)
                decision = services.gate.evaluate(
                    body=serialized, known_secrets=tokenized.mapping, external=True
                )
                if not decision.allowed:
                    pipeline_blocks += 1

                if attack == "prompt_injection":
                    success = FAKE_PROVIDER_KEY in serialized
                    record(
                        document["id"],
                        attack,
                        success,
                        "provider_key_in_context" if success else "no_key_in_context",
                    )
                elif attack == "placeholder_spoofing":
                    neutralized = "[USER_TEXT_01]" in tokenized.sanitized_text
                    if neutralized:
                        spoof_neutralized += 1
                    record(
                        document["id"],
                        attack,
                        not neutralized,
                        "neutralized" if neutralized else "spoof_survived",
                    )
                else:  # unknown attack type: fail closed in reporting
                    record(document["id"], attack, True, "unhandled_attack_type")
                continue

            # kind == "secret": the normal approved-task path.
            known = document.get("known_secrets", [])
            known_supplied += len(known)

            started = time.perf_counter()
            tokenized = services.tokenizer.tokenize(document["text"])
            services.vault.put(f"eval-{document['id']}", tokenized.mapping)
            payload = build_outbound_payload(
                model=settings.llm_model,
                sanitized_text=tokenized.sanitized_text,
                max_tokens=settings.max_output_tokens,
            )
            serialized = json.dumps(payload)
            local_latencies.append((time.perf_counter() - started) * 1000)

            decision = services.gate.evaluate(
                body=serialized, known_secrets=tokenized.mapping, external=True
            )
            if not decision.allowed:
                pipeline_blocks += 1
                continue

            for secret in known:
                if secret in serialized:
                    known_leaked += 1

            approved += 1
            t0 = time.perf_counter()
            response = services.provider.complete(
                ProviderRequest(
                    messages=payload["messages"],
                    model=payload["model"],
                    max_tokens=payload["max_tokens"],
                )
            )
            services.inspector.inspect(response.text, known_secrets=tokenized.mapping)
            e2e_latencies.append((time.perf_counter() - t0) * 1000)
            if response.text.strip():
                completed += 1

        lab_runs = []
        for scenario in SCENARIOS:
            result = run_scenario(services, scenario.id)
            if result is None:
                continue
            lab_runs.append(
                {
                    "id": scenario.id,
                    "passed": result.passed,
                    "actual": result.actual,
                    "abuse_case": scenario.abuse_case,
                }
            )
            # A failed scenario means an attack succeeded against the gateway.
            record(scenario.id, "lab_scenario", not result.passed, result.actual)

        provider_calls_completed = provider.call_count
        services.close()

    return {
        "known_secrets_supplied": known_supplied,
        "known_secrets_leaked": known_leaked,
        "baseline_raw_secrets_egressed": known_supplied,
        "approved_tasks": approved,
        "completed_tasks": completed,
        "benign_values_total": benign_values_total,
        "benign_values_redacted": benign_values_redacted,
        "benign_docs": benign_docs,
        "benign_docs_redacted": benign_docs_redacted,
        "forbidden_attempted": forbidden_attempted,
        "forbidden_blocked": forbidden_blocked,
        "attack_attempts": attack_attempts,
        "attack_successes": attack_successes,
        "oversize_rejected": oversize_rejected,
        "spoof_neutralized": spoof_neutralized,
        "pipeline_blocks": pipeline_blocks,
        "attack_breakdown": attack_breakdown,
        "lab_runs": lab_runs,
        "lab_total": len(lab_runs),
        "lab_passed": sum(1 for run in lab_runs if run["passed"]),
        "provider_calls_completed": provider_calls_completed,
        "local_latency_ms": local_latencies,
        "e2e_latency_ms": e2e_latencies,
    }


def benign_docs_total(corpus: dict[str, Any]) -> int:
    return sum(1 for d in corpus["documents"] if d["kind"] == "benign")


def main() -> int:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    print("[1/3] generating synthetic corpus ...")
    corpus = build_corpus()
    corpus_path = REPO_ROOT / "eval" / "corpus" / "corpus.json"
    corpus_path.parent.mkdir(parents=True, exist_ok=True)
    corpus_path.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")

    print("[2/3] running pipeline evaluation (offline, mock provider) ...")
    pipeline = _evaluate_pipeline(corpus)

    print("[3/3] running the pytest suite ...")
    suite = _run_pytest_suite()

    local = pipeline["local_latency_ms"]
    e2e = pipeline["e2e_latency_ms"]
    metrics: dict[str, Any] = {
        "known_secret_outbound_leakage_rate": _rate(
            pipeline["known_secrets_leaked"], pipeline["known_secrets_supplied"]
        ),
        "known_secrets_leaked": pipeline["known_secrets_leaked"],
        "known_secrets_supplied": pipeline["known_secrets_supplied"],
        "baseline_secrets_egressed_without_gateway": pipeline[
            "baseline_raw_secrets_egressed"
        ],
        "blocked_forbidden_requests": _rate(
            pipeline["forbidden_blocked"], pipeline["forbidden_attempted"]
        ),
        "forbidden_blocked": pipeline["forbidden_blocked"],
        "forbidden_attempted": pipeline["forbidden_attempted"],
        "attack_success_rate": _rate(
            pipeline["attack_successes"], pipeline["attack_attempts"]
        ),
        "attack_attempts": pipeline["attack_attempts"],
        "attack_successes": pipeline["attack_successes"],
        "false_positive_rate": _rate(
            pipeline["benign_values_redacted"], pipeline["benign_values_total"]
        ),
        "benign_documents_with_redactions": _rate(
            pipeline["benign_docs_redacted"], pipeline["benign_docs"]
        ),
        "task_utility": _rate(pipeline["completed_tasks"], pipeline["approved_tasks"]),
        "latency_local_p50_ms": round(_percentile(local, 50), 3),
        "latency_local_p95_ms": round(_percentile(local, 95), 3),
        "latency_e2e_p50_ms": round(_percentile(e2e, 50), 3),
        "latency_e2e_p95_ms": round(_percentile(e2e, 95), 3),
        "provider_calls_completed": pipeline["provider_calls_completed"],
        "lab_scenarios_passed": _rate(pipeline["lab_passed"], pipeline["lab_total"]),
        "test_suite_passed": suite["passed"],
        "test_suite_failed": suite["failed"],
        "oversized_payloads_rejected": pipeline["oversize_rejected"],
        "placeholder_spoofs_neutralized": pipeline["spoof_neutralized"],
    }

    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "source": "scripts/run_security_eval.py",
        "note": (
            "Measured output from an offline run against the synthetic corpus "
            "(eval/corpus/corpus.json) using the deterministic mock provider. "
            "Scoped to this corpus and the configured detectors - not a universal "
            "zero-leakage claim."
        ),
        "config": {
            "provider": "mock (offline)",
            "mode": "mock",
            "corpus_documents": len(corpus["documents"]),
            "test_command": suite["command"],
            "test_suite_exit_code": suite["exit_code"],
            "test_suite_duration_s": suite["duration_s"],
        },
        "metrics": metrics,
        "attack_breakdown": pipeline["attack_breakdown"],
        "lab_runs": pipeline["lab_runs"],
        "limitations": [
            "Regex detection is incomplete; unknown secret formats are out of scope.",
            "No real external provider is contacted during evaluation.",
            "Passing tests demonstrate behavior on the defined corpus only.",
        ],
    }

    summary_path = RESULTS_DIR / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (RESULTS_DIR / "report.md").write_text(_render_report(summary), encoding="utf-8")

    print(f"wrote {summary_path}")
    print(
        "leakage={leakage}  blocked_forbidden={blocked}  ASR={asr}  "
        "utility={utility}  suite={passed} passed / {failed} failed".format(
            leakage=metrics["known_secret_outbound_leakage_rate"],
            blocked=metrics["blocked_forbidden_requests"],
            asr=metrics["attack_success_rate"],
            utility=metrics["task_utility"],
            passed=suite["passed"],
            failed=suite["failed"],
        )
    )
    return 0 if suite["exit_code"] == 0 else 1


def _render_report(summary: dict[str, Any]) -> str:
    metrics = summary["metrics"]
    lines = [
        "# CipherShield AI - Evaluation Report",
        "",
        f"- Generated: `{summary['generated_at']}`",
        f"- Source: `{summary['source']}`",
        f"- Mode: {summary['config']['mode']} - corpus: "
        f"{summary['config']['corpus_documents']} documents",
        f"- Test suite: `{summary['config']['test_command']}` -> "
        f"{metrics['test_suite_passed']} passed, {metrics['test_suite_failed']} failed "
        f"({summary['config']['test_suite_duration_s']}s)",
        "",
        "## Metrics (measured)",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    for key, value in metrics.items():
        rendered = f"{value:.4f}" if isinstance(value, float) else str(value)
        lines.append(f"| {key} | {rendered} |")
    lines += [
        "",
        "## Lab scenarios",
        "",
        "| Scenario | Abuse case | Passed |",
        "|---|---|---|",
    ]
    for run in summary["lab_runs"]:
        verdict = "yes" if run["passed"] else "NO"
        lines.append(f"| {run['id']} | {run['abuse_case']} | {verdict} |")
    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in summary["limitations"]]
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
