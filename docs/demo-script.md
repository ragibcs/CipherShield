# Demo Script — CipherShield AI (2–3 minutes)

All data used in the demo is synthetic and generated locally.

| # | Time | Action | What to show |
|---|---|---|---|
| 1 | 20s | Paste a synthetic incident report containing a fake API token and an IP | The problem: raw secrets in analyst text |
| 2 | 25s | Run **Preview redaction** | Detected categories, counts, `[SECRET_01]` / `[IP_01]` placeholders, review step |
| 3 | 30s | Open the **outbound payload** view | Sanitized text only: raw token and key absent (search the payload live) |
| 4 | 25s | Click **Analyze securely** (mock provider) | Sanitized security summary + request ID; show `ALLOW_EXTERNAL_LLM=false` in status |
| 5 | 35s | Run the **prompt-injection** and **secret-extraction** scenarios in Security Lab | Policy decision, blocked outcome, provider call count unchanged |
| 6 | 20s | Tamper with a test ciphertext in the lab | AES-GCM authentication failure — fail closed |
| 7 | 20s | Open **Audit & Evaluation** | Measured metrics from `eval/results/summary.json`: leakage, blocked, latency |
| 8 | 10s | Close | Restate the trust boundary and the documented limitations |

## Rules

- Use only fake, synthetic secrets.
- If demonstrating a real external provider, disclose aloud that sanitized
  prompts still leave the local machine and may be processed under the
  provider's terms.
- Never paste a real credential into the demo — the screen recorder sees it.
