import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { graphFetch } from "./graph-fetch";

function mockResponse(status: number, headers: Record<string, string> = {}, body: string = "") {
  const res = {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (name: string) => headers[name] ?? null },
    text: async () => body,
  } as unknown as Response;
  (res as any).clone = () => res;
  return res;
}

describe("graphFetch", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("returns the response immediately on first-try success", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(200));
    vi.stubGlobal("fetch", fetchMock);

    const res = await graphFetch("https://graph.microsoft.com/v1.0/users");

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not retry on a non-throttling error status", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(403));
    vi.stubGlobal("fetch", fetchMock);

    const res = await graphFetch("https://graph.microsoft.com/v1.0/users");

    expect(res.status).toBe(403);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries on 429 and succeeds once the server stops throttling", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockResponse(429, { "Retry-After": "2" }))
      .mockResolvedValueOnce(mockResponse(200));
    vi.stubGlobal("fetch", fetchMock);

    const promise = graphFetch("https://graph.microsoft.com/v1.0/users");
    await vi.advanceTimersByTimeAsync(2000);
    const res = await promise;

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("honors the Retry-After header instead of exponential backoff when present", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockResponse(429, { "Retry-After": "10" }))
      .mockResolvedValueOnce(mockResponse(200));
    vi.stubGlobal("fetch", fetchMock);
    const onRetry = vi.fn();

    const promise = graphFetch("https://graph.microsoft.com/v1.0/users", {}, { onRetry });
    await vi.advanceTimersByTimeAsync(10_000);
    await promise;

    expect(onRetry).toHaveBeenCalledWith(1, 10_000, "HTTP 429");
  });

  it("retries on 503 the same way as 429", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockResponse(503))
      .mockResolvedValueOnce(mockResponse(200));
    vi.stubGlobal("fetch", fetchMock);

    const promise = graphFetch("https://graph.microsoft.com/v1.0/users", {}, { maxRetries: 2 });
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("gives up after maxRetries and returns the last throttled response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(429));
    vi.stubGlobal("fetch", fetchMock);

    const promise = graphFetch("https://graph.microsoft.com/v1.0/users", {}, { maxRetries: 2 });
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.status).toBe(429);
    expect(fetchMock).toHaveBeenCalledTimes(3); // initial attempt + 2 retries
  });

  it("retries a thrown network error by default and eventually succeeds", async () => {
    const fetchMock = vi.fn().mockRejectedValueOnce(new Error("ECONNRESET")).mockResolvedValueOnce(mockResponse(200));
    vi.stubGlobal("fetch", fetchMock);

    const promise = graphFetch("https://graph.microsoft.com/v1.0/users");
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("propagates a network error immediately when retryOnNetworkError is false", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("ECONNRESET"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      graphFetch("https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies", {}, { retryOnNetworkError: false })
    ).rejects.toThrow("ECONNRESET");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("retries a 401 'Lifetime validation failed' body and succeeds once the transient rejection clears", async () => {
    const lifetimeErrorBody = JSON.stringify({ error: { message: "Lifetime validation failed, the token is expired." } });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockResponse(401, {}, lifetimeErrorBody))
      .mockResolvedValueOnce(mockResponse(200));
    vi.stubGlobal("fetch", fetchMock);

    const promise = graphFetch("https://graph.microsoft.com/beta/deviceManagement/configurationPolicies");
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not retry a 401 for a real, unrelated auth failure", async () => {
    const realAuthError = JSON.stringify({ error: { message: "Access token is empty." } });
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(401, {}, realAuthError));
    vi.stubGlobal("fetch", fetchMock);

    const res = await graphFetch("https://graph.microsoft.com/v1.0/users");

    expect(res.status).toBe(401);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("gives up after its bounded retry budget and returns the still-failing 401 response", async () => {
    const lifetimeErrorBody = JSON.stringify({ error: { message: "Lifetime validation failed, the token is expired." } });
    const fetchMock = vi.fn().mockResolvedValue(mockResponse(401, {}, lifetimeErrorBody));
    vi.stubGlobal("fetch", fetchMock);

    const promise = graphFetch("https://graph.microsoft.com/beta/deviceManagement/configurationPolicies");
    await vi.runAllTimersAsync();
    const res = await promise;

    expect(res.status).toBe(401);
    // 1 initial attempt + 2 bounded retries for this specific error class.
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
