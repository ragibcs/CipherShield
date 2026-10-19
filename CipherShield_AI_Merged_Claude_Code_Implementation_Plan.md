# MANDATORY UPDATE --- Integrate the Competition Compliance Requirements

> **Use this update with the existing CipherShield AI codebase. Do not
> rebuild the project from scratch.** Claude Code must inspect the
> current repository, compare the existing implementation against these
> requirements, preserve working code and tests, and make targeted
> changes. This section takes precedence wherever the older plan is less
> specific.

## A. Updated objective

CipherShield AI must demonstrate the **AI Pipeline secret-isolation
track** described by the Mathematics for Systems Security rules:

-   Use a real hosted LLM API, such as an OpenAI-compatible endpoint,
    for at least one documented end-to-end demonstration.
-   Keep the master/vault key out of the agent prompt, provider request,
    frontend bundle, API responses, logs, and audit events.
-   Protect the original input within a clearly documented trusted
    boundary.
-   Send only an explicitly approved, sanitized prompt to the external
    provider.
-   Prove these properties with reproducible tests and a short video
    demonstration.
-   Deliver a clean, straightforward website or local TUI with a clear
    security-focused user experience.

**Important technical honesty:** A normal hosted LLM API cannot reason
directly over AES-encrypted ciphertext. CipherShield must not claim that
the external LLM can understand a fully encrypted prompt. The design
should instead distinguish (1) encrypted original input, (2) the trusted
local processing boundary, and (3) the readable but sanitized prompt
that is allowed to leave the machine. The original input is decrypted
only within the trusted backend boundary for detection and sanitization;
the master/vault key and raw secret mapping never go to the LLM. This is
a meaningful privacy control, but it is not fully homomorphic inference
or a guarantee that the provider cannot read the sanitized prompt.

If the organizer interprets "encrypting inputs to the agent" as
requiring ciphertext to remain encrypted during inference, document this
limitation and ask the organizer for clarification rather than
misrepresenting the implementation.

## B. New implementation requirements to merge into the existing project

### B1. Encrypted input envelope and trust-boundary documentation

1.  Add an input-protection layer before the analysis workflow.
2.  Document what protection applies to each hop:
    -   Browser to local backend: HTTPS/TLS if remote; localhost-only by
        default for the competition demo.
    -   Stored original input and secret mapping: encrypted at rest
        using authenticated encryption.
    -   Backend processing: plaintext may exist briefly inside the
        trusted backend process for detection and sanitization; never
        log it.
    -   Backend to LLM provider: only the policy-approved sanitized
        prompt over HTTPS.
3.  If implementing an application-level encrypted envelope, use a
    documented, standard construction and established libraries. Keep
    decryption private-key material in the trusted backend and out of
    the agent/provider. Do not invent a cryptographic scheme.
4.  Do not describe client-to-backend envelope encryption as protecting
    plaintext from the backend: the backend must decrypt it to analyze
    it.
5.  Fail closed if decryption, sanitization, policy evaluation, or
    outbound inspection fails.

### B2. Key separation and management

-   Clearly distinguish the application master key, vault encryption
    key, and LLM provider API credential.
-   Never send any of them to the LLM.
-   Use a documented key hierarchy. If a master key wraps a
    data-encryption key, implement and test the wrapping relationship;
    otherwise avoid calling a single local encryption key a complex key
    hierarchy.
-   Generate keys with a cryptographically secure random source. Never
    hardcode keys or commit local key files.
-   Keep keys separate from ciphertext storage where practical; set
    restrictive local file permissions for development.
-   Add key-rotation/invalid-key behavior documentation, even if full
    automated rotation is outside the MVP.
-   AES-256-GCM must use a fresh nonce for every encryption under the
    same key. Test altered ciphertext, altered tag, wrong key, malformed
    nonce, and malformed envelope.
-   Never claim protection against a compromised host, kernel, or
    privileged backend process.

### B3. Exact outbound request gate

Before every provider call, inspect the **exact serialized outbound
request**, not only the original input or an earlier prompt string.

The gate must: - Reject a request if any known original secret,
master/vault key, provider credential, forbidden field, or prohibited
tokenized value remains. - Check all outbound fields that can carry
content, including system/developer/user messages and tool arguments. -
Block the request before network I/O and emit a secret-free audit
event. - Have tests with a mock HTTP transport/interceptor proving that
blocked requests make zero provider calls. - Record only safe metadata:
request ID, policy decision, detector categories, provider/model label,
duration, and outcome.

Do not claim that pattern scanning detects every possible secret. Define
the supported detector coverage and residual risk.

### B4. Real hosted LLM evidence

-   Retain the deterministic mock provider for offline tests.
-   Add or verify a real OpenAI-compatible provider adapter with
    configurable base URL, model, timeout, and server-side API key.
-   Keep external calls disabled by default; require an explicit
    configuration/opt-in to enable them.
-   Run at least one real end-to-end analysis with a valid provider
    credential before submission, if the user has access to one.
-   Capture evidence of the provider/model configuration and sanitized
    request without exposing the API key or real sensitive data.
-   Never fake a provider response or label a mock run as a real API
    run.
-   In the README and demo, clearly label mock mode versus live-provider
    mode.

### B5. Response inspection and restoration

-   Inspect model output for known original secrets, configured secret
    patterns, unexpected placeholder manipulation, and prohibited
    disclosures.
-   Block or mask suspicious output by default.
-   Never automatically restore every placeholder.
-   Require an explicit, authorized user action for local restoration,
    apply policy checks, and write a secret-free audit event.
-   Test a malicious/mock provider response that repeats a known secret.

### B6. Competition demo and UI evidence

Build or refine the existing UI---do not replace it without a
reason---to make the trust boundary easy to understand.

The demo must visibly show: 1. A synthetic incident containing a fake
secret. 2. Detection and redaction preview. 3. The sanitized outbound
request, with raw secret absent. 4. A real hosted LLM analysis (clearly
labelled), plus mock mode for offline use. 5. A prompt-injection or
secret-extraction attempt being blocked. 6. A ciphertext-tampering test
failing authentication. 7. A test report with measured results and
limitations.

Use only synthetic secrets in screenshots and video. The website should
run locally/loopback by default unless deployment is explicitly
required. Include accessible status text; do not rely only on colors.

### B7. Evaluation metrics must come from real runs

Generate the dashboard/report from actual test output. At minimum
measure: - Known-secret outbound leakage count and rate. - Forbidden
requests blocked / forbidden requests attempted. - Unauthorized tool
attempts blocked. - Tampered ciphertext rejection. - False-positive
redaction rate on a defined benign test set. - Task utility after
sanitization. - Local and end-to-end latency. - Provider call count,
proving blocked requests never reached the provider.

Publish the test corpus size, test definitions, provider/model and
configuration, run date, and limitations. "Zero observed leakage" must
be scoped to the tested cases and detector coverage, not claimed
universally.

------------------------------------------------------------------------

## C. Claude Code instruction --- audit, implement, and merge with existing work

Paste the following prompt into Claude Code **from the existing
CipherShield AI repository root**. It is an incremental implementation
instruction, not a request to start a new repository.

> You are the lead security engineer and senior full-stack engineer for
> CipherShield AI, an existing project for the Mathematics for Systems
> Security AI Pipeline track.
>
> **Your mission:** integrate the new competition-compliance
> requirements into the current codebase and existing implementation
> plan. Preserve working code, tests, UI, configuration, and
> documentation wherever possible. Do not rebuild from scratch,
> overwrite files blindly, or remove features just to fit a new
> architecture.
>
> **First: audit only.** 1. Inspect the repository structure,
> `CLAUDE.md`, README, implementation plan, backend/frontend code,
> environment/configuration handling, tests, Docker files, and Git
> status. 2. Identify which requirements are implemented, partially
> implemented, missing, or unsafe. Cite actual file paths and relevant
> code locations in your report. 3. Run the existing tests and
> build/lint/type checks that are available. Record commands and actual
> results; do not claim unrun checks passed. 4. Identify the current
> trusted boundary and exactly where plaintext exists, where ciphertext
> exists, what the LLM receives, and where each key is stored. 5.
> Present a concise, ordered change plan with risks and files to be
> changed. Do not make broad code changes until this audit is
> summarized.
>
> **Then implement in small phases, updating the existing docs as you
> go.**
>
> **Phase 1 --- Security boundary and key separation** - Update
> `security/threat-model.md`, `security/security-invariants.md`, and
> architecture documentation to distinguish encrypted original input,
> trusted local processing, sanitized readable LLM input, and provider
> boundary. - Make the key hierarchy explicit: application master key
> (if used), vault/data-encryption key, and provider API credential are
> distinct roles. - Keep keys server-side, out of prompts, frontend
> bundles, API responses, logs, and audit events. - Use established
> cryptographic libraries only. Use AES-256-GCM with a fresh random
> nonce for each encryption under a given key. Do not invent
> cryptography. - Add or improve encrypted-input envelope handling only
> where it provides a clear, documented security benefit. Do not imply
> that the backend cannot read data it must decrypt to process.
>
> **Phase 2 --- Exact outbound request gate** - Enforce policy on the
> exact serialized provider request immediately before network I/O. -
> Inspect every outbound message and any tool arguments for known
> secrets, key material, forbidden fields, and policy violations. - Fail
> closed on detector errors, decryption errors, policy errors, or
> serialization uncertainty. - Prove with tests and a mock HTTP
> transport that blocked requests make zero provider calls. - Keep audit
> logs secret-free.
>
> **Phase 3 --- Hosted provider evidence** - Preserve mock mode and
> add/fix a configurable OpenAI-compatible provider adapter. - Keep the
> API key server-side, enforce timeouts and input/output limits, and
> disable external calls by default. - Ensure the UI clearly
> distinguishes mock mode from a real provider call. - Add tests for
> missing credentials, timeout, malformed response, provider errors, and
> no outbound call when policy blocks the request. - Do not invent
> credentials or fake a successful live call. If no valid key is
> available, finish the code and tests, document that live-provider
> verification remains pending, and ask the user to run it with their
> own key.
>
> **Phase 4 --- Response inspection and restore authorization** -
> Inspect provider output for known-secret leakage and suspicious
> placeholder manipulation. - Keep output sanitized by default. - Make
> restoration explicit, authorized, policy-checked, and audited. - Add
> adversarial tests for a provider response that repeats a known secret.
>
> **Phase 5 --- Competition UI and security lab** - Refine existing
> components instead of replacing the UI wholesale. - Provide a clear
> analysis workflow, redaction preview, exact sanitized outbound request
> view, provider mode label, attack simulator, tampered-ciphertext test,
> and evaluation report. - Use synthetic fixtures only. Never place
> actual keys or secrets in screenshots, logs, sample data, or demo
> video. - Metrics must be calculated from actual test results, never
> hardcoded.
>
> **Phase 6 --- Verification and submission** - Run backend
> unit/integration/adversarial tests, frontend tests, lint, type checks,
> build, and Docker smoke tests that are available. - Add or update
> GitHub Actions to run the repeatable checks. - Verify a clean-clone
> mock-mode demo works without a real API key. - Verify a live-provider
> test if a valid user-provided key is available; never claim it was run
> if it was not. - Update README, `CLAUDE.md`, architecture, threat
> model, security invariants, evaluation protocol, demo script, and
> submission checklist so they match the actual implementation. -
> Produce a final compliance matrix with: requirement, implementation
> path, test/evidence path, result, and remaining limitation.
>
> **Non-negotiable safety and engineering rules** - Never print, commit,
> or expose API keys, master keys, vault keys, plaintext secret
> mappings, or real sensitive user data. - Never run destructive Git
> commands or discard uncommitted user changes. - Do not overwrite
> existing work without inspecting it and explaining why a change is
> needed. - Do not add a new cryptographic algorithm. The selected track
> permits pre-existing cryptographic algorithms. - Do not claim full
> homomorphic encryption, formal verification, universal zero leakage,
> or protection from a compromised host unless implemented and
> independently justified. - Tests must verify behavior, not merely
> assert that a function exists. - Work one phase at a time. After each
> phase, report files changed, tests actually run, results, unresolved
> risks, and stop at the phase gate before continuing.
>
> Start now with the repository audit only. Do not implement until you
> have summarized the current state and proposed changes.

------------------------------------------------------------------------

## D. Updated acceptance criteria

Do not mark the project ready merely because the UI loads. The merged
implementation is ready for submission only when:

-   [ ] Existing functionality is preserved or any removal is justified.
-   [ ] The trust boundary and plaintext/ciphertext lifecycle are
    documented accurately.
-   [ ] Master/vault keys and provider credentials never enter outbound
    LLM requests or client code.
-   [ ] The exact serialized outbound request is inspected immediately
    before sending.
-   [ ] A blocked request is proven to cause zero provider calls.
-   [ ] AES-GCM tamper and wrong-key tests pass.
-   [ ] Provider output secret-leakage tests pass.
-   [ ] Mock mode works offline; live provider mode is clearly
    distinguished.
-   [ ] At least one real hosted-provider run is recorded if credentials
    are available.
-   [ ] UI shows redaction, provider mode, security decisions, and
    actual evaluation evidence.
-   [ ] Metrics are generated from repeatable test runs.
-   [ ] README and demo disclose limitations and do not overclaim
    encrypted inference.
-   [ ] Tests, lint, type checks, build, and Docker smoke tests pass
    where configured.
-   [ ] The Devpost submission includes a concise video showing the
    security boundary and attack tests.

**Priority:** Preserve working implementation → prove master-key
isolation → enforce exact outbound gate → validate provider integration
→ demonstrate attacks and evidence → polish UI. Cut optional features
before weakening security controls.

------------------------------------------------------------------------

------------------------------------------------------------------------

# Original implementation plan (retained)

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

  --------------------------------------------------------------------------
  Method                Endpoint                       Purpose
  --------------------- ------------------------------ ---------------------
  `GET`                 `/health`                      Liveness only; no
                                                       secrets or config
                                                       values

  `GET`                 `/api/v1/config/status`        Return whether
                                                       provider
                                                       configuration is
                                                       present, never the
                                                       key

  `POST`                `/api/v1/analyze/preview`      Detect secrets and
                                                       return a redaction
                                                       preview

  `POST`                `/api/v1/analyze`              Apply policy and
                                                       optionally call the
                                                       configured LLM

  `GET`                 `/api/v1/audit`                Return sanitized
                                                       audit events

  `GET`                 `/api/v1/evaluation/summary`   Return metrics
                                                       generated from
                                                       evaluation results

  `POST`                `/api/v1/vault/restore`        Restore selected
                                                       placeholders only
                                                       after authorization
                                                       and policy checks
  --------------------------------------------------------------------------

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
