import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AnalyzePage from "@/app/analyze/page";

const CONFIG = {
  app_env: "development",
  version: "0.1.0",
  provider: "mock",
  external_enabled: false,
  provider_configured: false,
  external_calls_enabled: false,
  restore_enabled: false,
  detector_categories: ["api_token", "email", "ipv4"],
  max_input_chars: 20000,
  max_output_tokens: 1200,
};

const PREVIEW = {
  request_id: "req_test_1",
  counts: { api_token: 1, email: 1, ipv4: 1 },
  findings: [
    {
      category: "api_token",
      placeholder: "[SECRET_01]",
      value: "sk-fake-1234567890abcdef",
      start: 0,
      end: 26,
    },
    {
      category: "email",
      placeholder: "[EMAIL_01]",
      value: "oncall@example.org",
      start: 30,
      end: 48,
    },
    {
      category: "ipv4",
      placeholder: "[IP_01]",
      value: "203.0.113.42",
      start: 52,
      end: 64,
    },
  ],
  sanitized_text: "token [SECRET_01] owner [EMAIL_01] from [IP_01]",
  detector_coverage_note: "Regex detection is intentionally incomplete.",
};

function stubFetch() {
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/analyze/preview")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => PREVIEW,
      } as Response);
    }
    if (url.includes("/config/status")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => CONFIG,
      } as Response);
    }
    if (url.includes("/api/v1/analyze")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({
          status: "completed",
          request_id: "req_test_2",
          counts: PREVIEW.counts,
          sanitized_text: PREVIEW.sanitized_text,
          policy: { allowed: true, code: "ok", reason: "Payload passed the outbound policy gate." },
          provider: "mock",
          model: "mock-echo",
          latency_ms: 1.5,
          output: "Mock analysis complete.",
          response_inspection: {
            action: "allow",
            masked_count: 0,
            leak_detected: false,
            counts: {},
          },
          outbound_body: '{"model":"mock-echo"}',
          provider_calls: 1,
        }),
      } as Response);
    }
    return Promise.resolve({
      ok: false,
      status: 404,
      json: async () => ({ error: { code: "not_found", message: "nope" } }),
    } as Response);
  });
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

describe("AnalyzePage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("previews redaction and shows placeholders instead of raw values", async () => {
    stubFetch();
    render(<AnalyzePage />);

    const previewButton = await screen.findByRole("button", {
      name: /preview redaction/i,
    });
    fireEvent.click(previewButton);

    // Placeholder column appears...
    expect(await screen.findByText("[SECRET_01]")).toBeInTheDocument();
    expect(await screen.findByText("[EMAIL_01]")).toBeInTheDocument();
    expect(await screen.findByText("[IP_01]")).toBeInTheDocument();
    // ...and the sanitized outbound text panel exists.
    expect(screen.getByText(/sanitized outbound text/i)).toBeInTheDocument();
    // External disclosure note reflects mock mode.
    expect(screen.getByText(/external calls are disabled/i)).toBeInTheDocument();
  });

  it("runs a secure analysis and renders policy status + request id", async () => {
    stubFetch();
    render(<AnalyzePage />);

    const analyzeButton = await screen.findByRole("button", {
      name: /analyze securely/i,
    });
    fireEvent.click(analyzeButton);

    expect(await screen.findByText("Analysis result")).toBeInTheDocument();
    expect(screen.getByText("req_test_2")).toBeInTheDocument();
    expect(screen.getByText("Mock analysis complete.")).toBeInTheDocument();
    expect(screen.getByText("ok")).toBeInTheDocument(); // policy code badge
  });
});
