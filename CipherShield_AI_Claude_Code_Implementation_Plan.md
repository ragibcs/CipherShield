# CipherShield AI --- Claude Code Implementation Plan

**Project:** CipherShield AI\
**Competition:** Mathematics for Systems Security --- AI Pipeline Track\
**Submission deadline:** 1 November 2026, 5:00 PM UTC+3 (**8:00 PM
Bangladesh time**)\
**Build approach:** Security-first, test-driven, incremental
implementation with Claude Code\
**MVP goal:** Demonstrate that an AI agent can analyze sensitive
security data through an LLM API while the master key and raw secrets
remain outside the agent and external provider boundary.

------------------------------------------------------------------------

## 1. Product Vision

CipherShield AI is a local-first security gateway for LLM-powered
workflows. It lets a user submit a security incident report, log
excerpt, or sample API trace for AI analysis while reducing the chance
that secrets are disclosed to the external model provider.

Before a request leaves the trusted backend, the system detects
sensitive values, replaces them with opaque placeholders, and records a
local mapping in an encrypted vault. The LLM receives only the sanitized
version. A policy-controlled local response processor can restore
selected values only when explicitly authorized.

**Core principle:** The LLM should not receive the master key, vault
encryption key, raw secret mapping, or secrets that are not required for
the task.

### Claims the project may make

-   The master key is not included in prompts or outbound LLM requests.
-   Known sensitive values detected by the configured scanner are
    replaced before provider submission.
-   Vault ciphertext is authenticated; modified ciphertext fails
    verification.
-   Tool calls are restricted by an explicit allowlist and policy.
-   The test suite measures observed leakage and attack success for its
    defined test cases.

### Claims the project must not make without additional evidence

-   "Zero knowledge" in the formal cryptographic sense.
-   Protection against a fully compromised host, kernel, or privileged
    backend process.
-   Detection of every possible secret or prompt injection.
-   End-to-end confidentiality for any raw content deliberately sent to
    a third-party provider.
-   Formal security proof merely because tests pass.

Use the phrase **"local-first secret-isolating AI gateway"** in the
README and demo unless a formal definition justifies a stronger term.

------------------------------------------------------------------------

## 2. MVP Scope

### Must-have features

1.  **Security analysis workspace**
    -   Paste or upload a small text incident report or log sample.
    -   Show detected sensitive values and categories before processing.
    -   Let the user review the proposed redactions.
    -   Show the sanitized prompt that will be sent to the model.
2.  **Secret detection and tokenization**
    -   Detect common API-token patterns, bearer tokens, passwords in
        common key/value formats, email addresses, and IPv4 addresses.
    -   Use deterministic placeholder IDs such as `[SECRET_01]`,
        `[EMAIL_01]`, and `[IP_01]`.
    -   Keep original-to-token mappings in the backend only.
    -   Make the detector modular so new patterns can be added and
        tested.
    -   Explain that regex detection is incomplete and should not be
        treated as a universal DLP solution.
3.  **Local encrypted vault**
    -   Use AES-256-GCM through the maintained Python `cryptography`
        package.
    -   Use a cryptographically secure random nonce for each encryption
        operation.
    -   Store nonce, ciphertext, and authentication tag in a documented
        format.
    -   Keep the encryption key separate from ciphertext storage.
    -   For the local demo, load a development key from an environment
        variable or a locally generated key file with restrictive
        permissions. Never commit it.
    -   Design a key-provider interface so a production KMS can be added
        later.
    -   Never log plaintext secrets, encryption keys, provider
        credentials, or the full token mapping.
4.  **LLM provider adapter**
    -   Support an OpenAI-compatible chat-completions endpoint through a
        configurable base URL, model name, and API key.
    -   Keep provider credentials server-side and out of the browser.
    -   Send only sanitized content to the provider.
    -   Use strict timeouts, bounded input/output sizes, and safe error
        messages.
    -   Do not silently fall back to another provider.
    -   Include a deterministic mock provider for offline tests and
        demos.
5.  **Policy enforcement**
    -   Define explicit policies for data categories that may leave the
        local boundary.
    -   Block outbound requests if a forbidden value remains after
        sanitization.
    -   Deny tools by default; only explicitly allowlisted tools can
        run.
    -   No shell, arbitrary filesystem, network-fetch, or code-execution
        tool in the MVP.
    -   Require user confirmation before any future action that changes
        external systems.
6.  **Response inspection**
    -   Scan model output for known original secrets and other
        configured sensitive patterns.
    -   Block or mask a response that appears to reveal a secret.
    -   Do not automatically rehydrate every placeholder. Rehydration
        must be an explicit, policy-checked user action.
    -   Keep the default output sanitized.
7.  **Audit trail**
    -   Record timestamp, request ID, policy decision, detector
        categories, provider/model identifier, latency, and outcome.
    -   Never record raw prompt text, raw model output, secrets, API
        keys, or vault mappings by default.
    -   Make the audit log tamper-evident with a documented hash-chain
        design if time permits.
    -   Do not describe a hash chain as preventing an administrator from
        rewriting the entire log unless a trusted external anchor
        exists.
8.  **Security evaluation dashboard**
    -   Show total tests, blocked requests, detected secrets, observed
        leakage events, unauthorized tool attempts, and latency.
    -   Generate the metrics from test results rather than hardcoded
        numbers.
    -   Clearly label synthetic demo data and actual test results.

### Explicitly out of scope for the deadline

-   Multi-tenant production SaaS.
-   Real cloud KMS integration unless the MVP is already stable.
-   Distributed agents and complex autonomous planning.
-   Arbitrary MCP server execution.
-   Full document OCR or enterprise DLP.
-   Claims of formal verification.
-   Automatic incident remediation in real systems.

------------------------------------------------------------------------

## 3. Recommended Technology Stack

  -----------------------------------------------------------------------
  Layer                   Technology              Reason
  ----------------------- ----------------------- -----------------------
  Web UI                  Next.js, TypeScript     Fast, polished
                                                  interactive interface

  Styling                 Tailwind CSS, shadcn/ui Consistent accessible
                                                  components

  Icons                   Lucide                  Clear, consistent UI
                                                  iconography

  Backend API             Python 3.12+, FastAPI,  Typed request
                          Pydantic                validation and simple
                                                  API surface

  Cryptography            `cryptography`          Established AES-GCM
                                                  primitives; do not
                                                  invent crypto

  Secret detection        Custom modular          Transparent,
                          detectors + tested      explainable MVP
                          patterns                behavior

  LLM API                 OpenAI-compatible HTTP  Supports configurable
                          client or SDK           compatible providers

  HTTP client             `httpx`                 Timeouts and controlled
                                                  outbound requests

  Database                SQLite for MVP          Minimal setup; use
                                                  SQLAlchemy if
                                                  persistence is needed

  Key/config handling     Environment variables + Keeps secrets outside
                          local key provider      source code
                          abstraction             

  Testing                 pytest, pytest-asyncio, Unit, integration, and
                          HTTPX TestClient        API tests

  Frontend tests          Vitest + React Testing  UI and end-to-end
                          Library; Playwright for coverage
                          critical flows          

  Quality                 Ruff, mypy or pyright,  Consistent code and
                          ESLint, Prettier        static checks

  Packaging               Docker Compose          Reproducible local demo

  CI                      GitHub Actions          Automated lint and test
                                                  checks

  Documentation           Markdown, Mermaid       Clear architecture and
                                                  evidence
  -----------------------------------------------------------------------

**Runtime configuration:** All API keys, base URLs, model names, and
local key paths must be configurable from environment variables or a
local settings page that writes to a server-side configuration
mechanism. Never expose a provider API key to client-side JavaScript.
For a competition demo, do not build a complex credential-management
service.

### Suggested environment variables

``` dotenv
APP_ENV=development
BACKEND_HOST=0.0.0.0
BACKEND_PORT=8000
DATABASE_URL=sqlite:///./data/ciphershield.db

LLM_BASE_URL=https://api.example.com/v1
LLM_MODEL=your-model-name
LLM_API_KEY=
LLM_TIMEOUT_SECONDS=30

CIPHERSHIELD_KEY_FILE=./secrets/local-master.key
ALLOW_EXTERNAL_LLM=false
MAX_INPUT_CHARS=20000
MAX_OUTPUT_TOKENS=1200
```

These are example settings, not valid credentials. Keep `.env` and the
`secrets/` directory out of Git. The app should refuse external calls
unless the user explicitly enables them and the provider configuration
validates.

**Key terminology:** In the MVP, use a dedicated **vault encryption
key** to encrypt vault records. If a separate application master key
derives or wraps that key, document the hierarchy clearly. Never send
either key to the LLM. Avoid reusing one key for encryption,
authentication, and unrelated purposes.

------------------------------------------------------------------------

## 4. Architecture

``` mermaid
flowchart TD
    U[User / Browser] --> UI[Next.js UI]
    UI --> API[FastAPI Backend]
    API --> VAL[Input Validation and Size Limits]
    VAL --> DET[Secret Detection and Tokenization]
    DET --> POL[Outbound Policy Gate]
    POL -->|Blocked| AUD[Secret-Free Audit Event]
    POL -->|Approved Sanitized Payload| LLM[OpenAI-Compatible Provider]
    LLM --> OUT[Output Inspection]
    OUT --> POL2[Response Policy Gate]
    POL2 --> UI
    DET <--> VAULT[Local Encrypted Vault]
    VAULT --> KEYS[Local Key Provider]
    API --> AUD
    POL2 --> AUD
```

### Trust boundaries

-   **Browser:** untrusted. Never put provider credentials or vault keys
    here.
-   **Backend:** trusted for the MVP, but must avoid secret leakage
    through logs, exceptions, traces, and debug endpoints.
-   **Vault:** stores encrypted mappings. The encryption key is not
    stored beside ciphertext in production.
-   **External LLM provider:** outside the trusted boundary. Assume it
    can retain or inspect submitted prompts according to its own terms.
-   **Audit store:** should contain only minimal, secret-free metadata.

### Request flow

1.  Validate request size, type, and configuration.
2.  Identify sensitive values and display a redaction preview.
3.  Create opaque placeholders and encrypt the mapping locally.
4.  Run the outbound policy gate over the exact serialized request.
5.  If any forbidden sensitive value remains, block the request.
6.  Send sanitized text only when external calls are explicitly enabled.
7.  Inspect the response for known-secret disclosure and policy
    violations.
8.  Return a sanitized result and a request ID.
9.  Write a secret-free audit event.
10. Permit local placeholder restoration only after an explicit,
    authorized user action.

------------------------------------------------------------------------

## 5. Repository Structure

Use a monorepo:

``` text
ciphershield-ai/
├── apps/
│   └── web/                       # Next.js frontend
│       ├── app/
│       ├── components/
│       ├── lib/
│       └── tests/
├── services/
│   └── api/                       # FastAPI backend
│       ├── app/
│       │   ├── api/routes/
│       │   ├── core/
│       │   ├── schemas/
│       │   ├── services/
│       │   │   ├── detection/
│       │   │   ├── tokenization/
│       │   │   ├── vault/
│       │   │   ├── providers/
│       │   │   ├── policy/
│       │   │   ├── response_inspection/
│       │   │   └── audit/
│       │   └── main.py
│       └── tests/
├── security/
│   ├── threat-model.md
│   ├── security-invariants.md
│   ├── abuse-cases.md
│   └── evaluation-protocol.md
├── docs/
│   ├── architecture.md
│   ├── decisions/
│   ├── demo-script.md
│   └── submission-checklist.md
├── scripts/
│   ├── generate_demo_data.py
│   └── run_security_eval.py
├── .github/workflows/ci.yml
├── docker-compose.yml
├── .env.example
├── .gitignore
├── CLAUDE.md
├── README.md
└── LICENSE
```

Keep modules small and focused. Do not put detection, cryptography,
provider calls, policy decisions, and audit logging into one large
service class.

------------------------------------------------------------------------

## 6. API Design

Start with a small API surface:

  ------------------------------------------------------------------------------
  Method                  Endpoint                       Purpose
  ----------------------- ------------------------------ -----------------------
  `GET`                   `/health`                      Liveness only; no
                                                         secrets or config
                                                         values

  `GET`                   `/api/v1/config/status`        Return whether provider
                                                         configuration is
                                                         present, never the key

  `POST`                  `/api/v1/analyze/preview`      Detect secrets and
                                                         return a redaction
                                                         preview

  `POST`                  `/api/v1/analyze`              Apply policy and
                                                         optionally call the
                                                         configured LLM

  `GET`                   `/api/v1/audit`                Return sanitized audit
                                                         events

  `GET`                   `/api/v1/evaluation/summary`   Return metrics
                                                         generated from
                                                         evaluation results

  `POST`                  `/api/v1/vault/restore`        Restore selected
                                                         placeholders only after
                                                         authorization and
                                                         policy checks
  ------------------------------------------------------------------------------

### API safety rules

-   Validate with Pydantic models and strict size limits.
-   Add request IDs and safe error codes.
-   Do not return stack traces in production mode.
-   Do not include secrets in validation errors.
-   Protect state-changing endpoints against unauthorized access; if
    exposed beyond localhost, implement authentication and CSRF
    protections as appropriate.
-   Use rate limiting if exposed to a network.
-   Never make `/config/status` reveal environment variables, file
    paths, or key material.
-   Disable restore by default until authorization and audit tests pass.
-   The initial demo should bind to localhost unless remote access is
    explicitly configured.

------------------------------------------------------------------------

## 7. UI/UX Requirements

Create a polished, security-focused dashboard rather than a generic chat
clone.

### Main screens

1.  **Overview**
    -   Security status, recent requests, blocked attempts, and
        evaluation metrics.
    -   Clearly distinguish "configured," "tested," and "not yet
        verified."
2.  **Analyze**
    -   Input editor for a synthetic incident report.
    -   Detection summary and editable redaction preview.
    -   Sanitized outbound payload preview.
    -   "Analyze securely" button with a clear external-provider
        disclosure.
    -   Result panel with a policy status and request ID.
3.  **Vault**
    -   Show record IDs, categories, creation times, and encryption
        status.
    -   Never display the vault key.
    -   Reveal/restore only through a separate explicit confirmation
        flow.
4.  **Security Lab**
    -   Select attack scenarios: secret in prompt, prompt injection,
        forbidden field, tampered ciphertext, unauthorized tool request,
        and malicious model output.
    -   Run test and show expected vs actual behavior.
    -   Label each result with the test ID and whether it passed.
5.  **Audit & Evaluation**
    -   Secret-free timeline and test-generated metrics.
    -   Export a report containing no raw secrets.

### Visual direction

-   Premium dark interface with high-contrast text and restrained accent
    colors.
-   Use clear status text and icons; do not rely on color alone.
-   Show the trust boundary visually: local processing versus external
    provider.
-   Add loading, empty, error, blocked, and success states.
-   Ensure keyboard navigation, responsive layout, readable typography,
    and accessible contrast.
-   Never use fake security metrics in the live dashboard.

------------------------------------------------------------------------

## 8. Security Invariants

Create `security/security-invariants.md` before implementation. The
following must become automated tests:

1.  Master key and vault key never appear in the serialized LLM request.
2.  Provider API key never appears in frontend bundles, API responses,
    audit events, or application logs.
3.  A detected secret is replaced before external submission unless a
    user-approved policy explicitly allows it.
4.  If the outbound gate finds a forbidden value, no provider request
    occurs.
5.  Each AES-GCM encryption uses a fresh, cryptographically random nonce
    for a given key.
6.  Modified ciphertext or authentication tag is rejected.
7.  Vault plaintext mappings are not persisted unencrypted.
8.  Unknown tools and tool arguments are denied by default.
9.  Response inspection blocks or masks known-secret disclosure.
10. Error handling does not leak request content or cryptographic
    material.
11. No network call occurs in offline/mock-provider tests.
12. Placeholder restoration is explicit, authorized, and audited.
13. The app fails closed if encryption or policy evaluation fails.
14. External provider calls are disabled by default until the user
    explicitly enables them.

------------------------------------------------------------------------

## 9. Testing and Evaluation

### Test layers

**Unit tests** - Secret detectors, overlapping matches, tokenization,
placeholder collisions. - AES-GCM encrypt/decrypt round-trip. - Wrong
key, altered ciphertext, altered tag, and malformed nonce rejection. -
Policy rules, output scanner, audit redaction. - Provider timeout and
error normalization.

**Integration tests** - Preview → tokenization → policy → mock provider
→ response scan. - Forbidden secret blocks provider call. - Provider API
key is not returned by any endpoint. - No secrets in captured logs or
audit records. - Restore requires authorization and emits an audit
event.

**Adversarial tests** - Direct requests to reveal API keys. - Indirect
prompt injection in incident text. - Secret split across common
delimiters or whitespace. - Multiple secrets of the same category. -
Placeholder spoofing or collision attempts. - Model output that repeats
a known secret. - Tool-call request to a tool not on the allowlist. -
Malformed or oversized payloads. - Ciphertext tampering and wrong-key
attempts.

### Benchmark metrics

Report values from actual runs:

-   **Known-secret outbound leakage rate** = known test secrets found in
    outbound payloads / known test secrets supplied.
-   **Blocked forbidden requests** = forbidden requests blocked /
    forbidden requests attempted.
-   **Attack success rate** = successful policy violations / attack
    attempts.
-   **False-positive rate** = benign values incorrectly redacted /
    benign values evaluated.
-   **Task utility** = percentage of approved test tasks where the model
    returns a useful answer despite redaction.
-   **P50/P95 latency** for local processing and end-to-end requests.
-   **Provider-call count** to prove blocked requests never reached the
    provider.

Document the test corpus, number of runs, model/provider configuration,
and limitations. Never present synthetic numbers as measured results. A
"zero observed leakage" result must be scoped to the tested corpus and
detector coverage.

------------------------------------------------------------------------

## 10. Claude Code Workflow

Claude Code should implement the repository in small, verifiable phases.
Do not ask it to generate the entire application in one prompt.

### Phase 0 --- Inspect and plan

Ask Claude Code to: - Inspect the existing repository before editing. -
Create `CLAUDE.md`, threat model, architecture, security invariants,
implementation plan, and decision records. - Identify unresolved
security assumptions. - Propose a file-by-file plan and wait for
approval before broad code changes.

### Phase 1 --- Backend security core

Implement: - Pydantic schemas and request limits. - Secret detector
interface and initial detectors. - Deterministic tokenization. - AES-GCM
vault service. - Key-provider abstraction. - Policy gate. - Secret-free
audit events. - Unit tests for security invariants.

**Gate:** Do not proceed until backend unit tests pass and key/secret
leakage checks exist.

### Phase 2 --- Provider integration

Implement: - OpenAI-compatible provider adapter. - Mock provider. -
Explicit external-call opt-in. - Timeouts, error handling, request
limits. - Exact serialized outbound-payload inspection. - Tests proving
blocked requests do not call the provider.

**Gate:** Verify all tests pass with network access disabled.

### Phase 3 --- Response handling and API

Implement: - Response scanner. - Explicit restore authorization. - API
routes. - Safe logging and request IDs. - Integration tests.

**Gate:** No raw secrets in API responses, logs, or audit events.

### Phase 4 --- Frontend

Implement: - Dashboard, Analyze, Vault, Security Lab, Audit/Evaluation
screens. - Loading, empty, error, blocked, and success states. - Backend
integration through typed API helpers. - Accessible and responsive UI. -
UI tests for the core workflow.

**Gate:** Confirm no API key or vault key is present in browser source
or network payloads.

### Phase 5 --- Security lab and evaluation

Implement: - Synthetic test fixtures. - Attack scenarios and repeatable
test runner. - Metrics generated from test outputs. - Exportable
sanitized report. - A baseline comparison showing what happens without
the gateway versus with it.

**Gate:** Every chart/metric must link to a reproducible test result.

### Phase 6 --- Packaging and release

Implement: - Docker Compose and health checks. - `.env.example` with
placeholders only. - GitHub Actions for linting and tests. -
Production-safe configuration defaults. - README setup instructions,
architecture diagram, limitations, threat model, demo script, and
submission checklist.

**Gate:** A clean clone can run the demo using documented commands and
mock mode without an external API key.

------------------------------------------------------------------------

## 11. Initial Prompt for Claude Code

Paste this prompt into Claude Code from the project root:

> You are the lead security engineer and senior full-stack engineer for
> CipherShield AI, a competition MVP for the Mathematics for Systems
> Security AI Pipeline track.
>
> Build a local-first secret-isolating gateway for LLM-based security
> analysis. The product must demonstrate that a master/vault key and raw
> secrets are not sent to the external LLM provider. The system must use
> established cryptographic primitives and testable security policies,
> not custom cryptography.
>
> **Stack:** Next.js + TypeScript + Tailwind CSS + shadcn/ui; Python
> 3.12+ + FastAPI + Pydantic; `cryptography` with AES-256-GCM;
> configurable OpenAI-compatible provider adapter; SQLite if persistence
> is required; pytest, Vitest, Playwright, Ruff, ESLint, Docker Compose,
> and GitHub Actions.
>
> **Workflow:** inspect the repository first; do not overwrite existing
> work blindly. Create `CLAUDE.md`, `security/threat-model.md`,
> `security/security-invariants.md`, `docs/architecture.md`,
> `docs/implementation-plan.md`, and `docs/submission-checklist.md`.
> Then propose the phased implementation plan and wait for approval
> before large code changes.
>
> **Non-negotiable requirements:** 1. Provider API keys and vault keys
> must remain server-side. 2. External LLM calls must be disabled by
> default and enabled explicitly. 3. Detect and tokenize configured
> sensitive values before any external call. 4. Inspect the exact
> outbound serialized request and fail closed if policy violations
> remain. 5. Use AES-256-GCM from the maintained `cryptography` library
> with fresh random nonces. 6. Never log raw secrets, keys, raw prompts,
> or secret mappings. 7. Include a deterministic mock provider and tests
> that run without network access. 8. Deny unknown tools by default; do
> not implement shell execution or arbitrary network/file tools in the
> MVP. 9. Inspect model output for known-secret disclosure. 10. Make
> placeholder restoration explicit, authorized, and audited. 11.
> Generate dashboard metrics from real test results; never fabricate
> numbers. 12. Include adversarial tests and document limitations
> honestly.
>
> Implement in small phases. For each phase: state the planned changes,
> implement only that phase, run relevant tests and lint checks,
> summarize changed files and results, list unresolved risks, and stop
> at the phase gate. Do not claim tests passed unless you ran them. Do
> not claim formal verification or universal zero leakage.
>
> First, inspect the current repository and report its structure,
> existing stack, and proposed Phase 0 changes. Do not begin broad
> implementation until the plan is reviewed.

------------------------------------------------------------------------

## 12. Recommended Git Commit Strategy

Use small commits that correspond to tested milestones:

``` text
chore: scaffold monorepo and development tooling
docs: add threat model and security invariants
feat(api): add secret detection and tokenization
feat(security): implement AES-GCM local vault
feat(policy): add outbound request enforcement
feat(llm): add OpenAI-compatible and mock providers
feat(security): inspect model responses for secret leakage
feat(api): add secure analysis and audit endpoints
feat(web): add analysis workspace and security dashboard
feat(eval): add adversarial security test suite
test: verify secret isolation and fail-closed behavior
build: add Docker Compose and CI workflows
docs: add demo script and competition submission guide
```

Commit only after tests pass. Never commit `.env`, API keys, real
secrets, unredacted security logs, generated vault files, or private
test fixtures. Use a `.gitignore` and a pre-commit secret scanner.

------------------------------------------------------------------------

## 13. Demo Script (2--3 Minutes)

1.  **Show the problem (20 sec):** Paste a synthetic incident report
    containing a fake API token and an IP address.
2.  **Preview redaction (25 sec):** Show detected categories and
    tokenized text.
3.  **Prove the boundary (30 sec):** Display the sanitized outbound
    request and prove the raw fake token and keys are absent.
4.  **Run analysis (25 sec):** Use the mock provider or a configured
    OpenAI-compatible API; show the sanitized security summary.
5.  **Attack the system (35 sec):** Run a prompt-injection or
    secret-extraction test and show the policy decision.
6.  **Show cryptographic integrity (20 sec):** Tamper with a test
    ciphertext and show AES-GCM authentication failure.
7.  **Show evidence (20 sec):** Open the test report with observed
    leakage, blocked requests, task utility, and latency.
8.  **Close (10 sec):** Explain the trust boundary and the limitations
    honestly.

Use fake, synthetic secrets only. If demonstrating a real external
provider, disclose that sanitized prompts still leave the local machine
and may be processed under the provider's terms.

------------------------------------------------------------------------

## 14. Submission Checklist

### Product

-   [ ] Clean-clone setup works.
-   [ ] Mock-mode demo works without an API key.
-   [ ] OpenAI-compatible provider configuration is documented.
-   [ ] Secret preview and outbound sanitized payload are visible.
-   [ ] Master/vault keys remain backend-side.
-   [ ] Blocked requests demonstrably make no provider call.
-   [ ] Tampered ciphertext is rejected.
-   [ ] Response inspection and explicit restore flow are tested.
-   [ ] Security dashboard uses actual evaluation output.

### Security and quality

-   [ ] No real secrets or credentials in Git history.
-   [ ] `.env.example` contains placeholders only.
-   [ ] Unit, integration, and adversarial tests pass.
-   [ ] Lint and type checks pass.
-   [ ] External calls disabled by default.
-   [ ] Threat model and limitations are documented.
-   [ ] No unsupported "formally verified" or universal "zero leakage"
    claims.

### Submission

-   [ ] README includes problem, solution, architecture, setup, tests,
    limitations, and screenshots.
-   [ ] Demo video is short, clear, and uses synthetic data.
-   [ ] Repository is accessible to judges.
-   [ ] Competition-required fields and links are complete.
-   [ ] Submission is completed before **1 November 2026, 8:00 PM
    Bangladesh time**.

------------------------------------------------------------------------

## 15. Definition of Done

CipherShield AI is ready to submit when a judge can clone the
repository, run the app in mock mode, submit a synthetic incident,
inspect the redaction preview, observe a sanitized model request,
trigger a blocked attack, verify ciphertext tamper rejection, and
inspect reproducible test results---without needing access to a real
secret or master key.

**Priority order:** Correct security boundary → reproducible tests →
working demo → polished UI → optional features. If time gets tight, cut
optional features before weakening the security model.
