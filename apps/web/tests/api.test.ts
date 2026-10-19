import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api } from "@/lib/api";

function jsonResponse(payload: unknown, ok = true, status = 200) {
  return {
    ok,
    status,
    json: async () => payload,
  } as Response;
}

describe("api client", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts JSON with the right content type and body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await api.preview("incident text");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/analyze/preview");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe(
      "application/json",
    );
    expect(JSON.parse(String(init.body))).toEqual({ text: "incident text" });
  });

  it("surfaces backend error codes and messages", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            error: {
              code: "restore_not_authorized",
              message: "Restore is disabled on this instance.",
            },
          },
          false,
          403,
        ),
      ),
    );

    await expect(api.restore("r1", ["[SECRET_01]"], "token")).rejects.toMatchObject({
      code: "restore_not_authorized",
      status: 403,
      message: "Restore is disabled on this instance.",
    });
  });

  it("maps network failures to a friendly ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("Failed to fetch")),
    );

    await expect(api.configStatus()).rejects.toBeInstanceOf(ApiError);
    await expect(api.configStatus()).rejects.toMatchObject({
      code: "network_error",
      status: 0,
    });
  });

  it("never receives a provider API key from config status (server contract)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          app_env: "development",
          version: "0.1.0",
          provider: "mock",
          external_enabled: false,
          provider_configured: false,
          external_calls_enabled: false,
          restore_enabled: false,
          detector_categories: ["api_token"],
          max_input_chars: 20000,
          max_output_tokens: 1200,
        }),
      ),
    );
    const status = await api.configStatus();
    const serialized = JSON.stringify(status);
    expect(serialized).not.toContain("api_key");
    expect(serialized).not.toContain("LLM_");
    expect(Object.keys(status)).not.toContain("llm_api_key");
  });
});
