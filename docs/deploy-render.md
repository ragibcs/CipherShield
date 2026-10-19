# Deploying CipherShield AI to Render

Two Docker web services deploy from this repo via the included `render.yaml`
Blueprint: `ciphershield-api` (FastAPI) and `ciphershield-web` (Next.js).

The deployed demo keeps the local-first defaults: **external LLM calls are
disabled (mock provider)** and **vault restore is disabled** until you opt in.

## 0. Prerequisites

1. Push the repo to GitHub (all commits are local until you do):
   ```bash
   git remote add origin git@github.com:<you>/<repo>.git
   git push -u origin main
   ```
2. A free [Render](https://render.com) account.
3. Generate the vault encryption key you will paste during setup
   (**keep it somewhere safe — vault records are unreadable without it**):
   ```bash
   python3 -c "import secrets; print(secrets.token_hex(32))"
   ```

## 1. Deploy with the Blueprint (recommended)

1. Render Dashboard → **New → Blueprint** → connect/select your GitHub repo.
2. Render detects `render.yaml`. You will be prompted for three values:

   | Prompt (service) | What to enter | Example |
   |---|---|---|
   | `CIPHERSHIELD_KEY` (api) | the 64-char hex key from step 0 | `9f3c…` (64 hex chars) |
   | `ALLOWED_ORIGINS` (api) | the **web** service's URL (exact origin) | `https://ciphershield-web.onrender.com` |
   | `NEXT_PUBLIC_API_URL` (web) | the **api** service's URL | `https://ciphershield-api.onrender.com` |

   Notes:
   - Service URLs are `<service-name>.onrender.com`. If Render appends a
     suffix because the name was taken, use the URL it shows and correct
     `ALLOWED_ORIGINS` afterwards (Environment → edit → redeploy).
   - Both values must be `https://` and must not end with `/`.
3. Apply, wait for both services to build (first build ~3–6 min).

## 2. Verify the deployment

- `GET https://<api>/health` → `{"status":"ok"}`
- `GET https://<api>/api/v1/config/status` → booleans only; confirm
  `external_calls_enabled: false` and **no key material in the JSON**
- Open the web URL → Overview loads "External calls disabled" badge
- Analyze screen → **Preview redaction** → **Analyze securely** (mock mode)
- Security Lab → **Run all scenarios** → all PASS
- If the UI cannot reach the API (browser console CORS error): your
  `ALLOWED_ORIGINS` does not match the web URL exactly — fix and redeploy.

## 3. Manual setup (without Blueprint)

**Option A — all-in-one service (simplest):** one service from the repo-root
`Dockerfile`.

| Field | Value |
|---|---|
| Runtime | **Docker** |
| Dockerfile Path | `Dockerfile` |
| Docker Context | `.` |
| Health Check Path | `/health` |
| Env vars | none required — the browser uses same-origin `/api/*`, which the Next server proxies to the bundled API |

Everything runs behind the platform's single `$PORT` (UI + proxied API), so
HTTPS and CORS are non-issues. Leave `NEXT_PUBLIC_API_URL` unset; only set it
to point at a *different* origin.

**Option B — two services (recommended for production):** create two services
from the same repo:

**API — Web Service**

| Field | Value |
|---|---|
| Runtime | **Docker** |
| Dockerfile Path | `services/api/Dockerfile` |
| Docker Context | `services/api` (if not shown, use the Blueprint path) |
| Health Check Path | `/health` |
| Env vars | as in `render.yaml` (at minimum `CIPHERSHIELD_KEY`, `ALLOWED_ORIGINS`, `APP_ENV=production`, `ALLOW_EXTERNAL_LLM=false`) |

**Web — Web Service**

| Field | Value |
|---|---|
| Runtime | **Docker** |
| Dockerfile Path | `apps/web/Dockerfile` |
| Docker Context | `apps/web` |
| Health Check Path | `/` |
| Env vars | `NEXT_PUBLIC_API_URL=https://<api-url>`, `NEXT_TELEMETRY_DISABLED=1` |

## 4. Environment variable reference

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `CIPHERSHIELD_KEY` | **yes** | – | 64-hex vault key; read before the key file (INV: key stays server-side) |
| `ALLOWED_ORIGINS` | **yes** | localhost:3000 | Exact browser origin allowed by CORS |
| `NEXT_PUBLIC_API_URL` | **yes** | `http://127.0.0.1:8000` | API base for the browser bundle (**build-time** inlined) |
| `APP_ENV` | recommended | development | `production` disables `/docs` + OpenAPI |
| `ALLOW_EXTERNAL_LLM` | no | `false` | Keep `false` unless you intentionally enable a real provider |
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | no | – | Real OpenAI-compatible provider (server-side only) |
| `VAULT_RESTORE_TOKEN` | no | unset | Restore/rehydration stays disabled until set |
| `RATE_LIMIT_PER_MINUTE` | no | `60` | State-changing endpoint limiter |

## 5. Operational caveats (read before demo day)

- **Ephemeral disk on the free plan**: SQLite data (audit trail, vault
  ciphertext) and the container filesystem reset on redeploy. The
  `CIPHERSHIELD_KEY` env var keeps the *key* stable, but old records are gone
  after a redeploy — fine for a demo, not for real data. For persistence,
  attach a paid **Persistent Disk** at `/var/data` and set
  `DATABASE_URL=sqlite:////var/data/ciphershield.db`.
- **Free tier spin-down**: after idle time the web service sleeps; first
  request takes ~30–50 s. Warm both services before recording the demo video.
- **NEXT_PUBLIC_API_URL is baked at build time**: changing it requires a
  manual **Deploy → Clear build cache & deploy** (or any redeploy).
- **Vault key safety**: never commit it, never set it as `NEXT_PUBLIC_*`, and
  store a copy outside Render — losing it makes existing vault records
  permanently unreadable (by design, fail-closed).
- **Provider key safety**: if you enable a real provider, `LLM_API_KEY` lives
  only in Render's server-side env; `/api/v1/config/status` returns booleans,
  never values.
- **Region** in `render.yaml` is `singapore` and cannot be changed after
  creation (delete/recreate to move). It is close to Bangladesh (~20 ms).
- **Costs**: both services use `plan: free` (512 MB, spin-down). Persistent
  disks and always-on instances require a paid plan.

## 6. Redeploys and checks

- Pushes to `main` auto-deploy both services (default `autoDeployTrigger`).
- CI (`/.github/workflows/ci.yml`) runs lint/tests on push; you can switch
  `autoDeployTrigger` to `checksPass` in `render.yaml` to gate deploys on CI.
- Every deploy re-runs the health check (`/health`, `/`) with a warm-up
  window; a failed health check rolls the deploy back automatically.
