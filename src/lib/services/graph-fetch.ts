// Thin wrapper around fetch() for calls to Microsoft Graph / Entra ID endpoints.
// Retries on 429 (throttled) and 503 (service unavailable), honoring the server's
// Retry-After header when present, falling back to exponential backoff with jitter.
// Other HTTP statuses (401, 403, 404, 400...) are real errors and are returned
// as-is for the caller to handle — only throttling/transient failures are retried here.

export interface GraphFetchOptions {
  maxRetries?: number;
  // POST/PATCH/DELETE calls that create or mutate state should NOT retry on a raw
  // network exception (fetch throwing) — the request may have already reached the
  // server and been processed; retrying could double it. A 429/503 HTTP response is
  // always safe to retry regardless, since the server is explicitly saying it did
  // not process the request. GET calls are naturally safe to retry either way.
  retryOnNetworkError?: boolean;
  onRetry?: (attempt: number, delayMs: number, reason: string) => void;
}

const DEFAULT_MAX_RETRIES = 4;
const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 30_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function computeBackoffDelay(attempt: number): number {
  const exp = Math.min(BASE_DELAY_MS * 2 ** attempt, MAX_DELAY_MS);
  const jitter = Math.random() * exp * 0.25;
  return Math.round(exp + jitter);
}

function parseRetryAfterMs(header: string | null): number | null {
  if (!header) return null;
  const seconds = Number(header);
  if (!Number.isNaN(seconds)) return Math.min(seconds * 1000, MAX_DELAY_MS);
  const dateMs = Date.parse(header);
  if (!Number.isNaN(dateMs)) return Math.max(0, Math.min(dateMs - Date.now(), MAX_DELAY_MS));
  return null;
}

export async function graphFetch(url: string, init: RequestInit = {}, opts: GraphFetchOptions = {}): Promise<Response> {
  const maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
  const retryOnNetworkError = opts.retryOnNetworkError ?? true;

  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, init);
      const isThrottled = res.status === 429 || res.status === 503;
      if (isThrottled && attempt < maxRetries) {
        const retryAfterMs = parseRetryAfterMs(res.headers.get("Retry-After"));
        const delayMs = retryAfterMs ?? computeBackoffDelay(attempt);
        opts.onRetry?.(attempt + 1, delayMs, `HTTP ${res.status}`);
        await sleep(delayMs);
        continue;
      }
      return res;
    } catch (err) {
      if (!retryOnNetworkError || attempt >= maxRetries) throw err;
      const delayMs = computeBackoffDelay(attempt);
      opts.onRetry?.(attempt + 1, delayMs, err instanceof Error ? err.message : "network error");
      await sleep(delayMs);
    }
  }
}
