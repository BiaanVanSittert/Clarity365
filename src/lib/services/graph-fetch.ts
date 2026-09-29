// Thin wrapper around fetch() for calls to Microsoft Graph / Entra ID endpoints.
// Retries on 429 (throttled) and 503 (service unavailable), honoring the server's
// Retry-After header when present, falling back to exponential backoff with jitter.
// Other HTTP statuses (403, 404, 400...) are real errors and are returned
// as-is for the caller to handle - only throttling/transient failures are retried here.
//
// Also retries a 401 "Lifetime validation failed, the token is expired" - a
// documented, live-confirmed Microsoft backend quirk (see
// describeTransientTokenLifetimeError's own comment and graph-client.test.ts)
// where a genuinely valid, correctly-timed token is rejected by one specific
// Graph resource provider while every other call with the same token
// succeeds. Previously this retry was hand-rolled inline in exactly one
// caller (testAppRegistrationPermissions) and every other Graph call in the
// app - including deployEdrPolicy/fetchEdrPolicy and their AV/ASR
// equivalents - had no protection at all. Centralizing it here fixes every
// caller at once instead of requiring each one to duplicate the same
// try/wait/retry block. Bounded to 2 short (1.5s) retries specifically for
// this error - deliberately not the same exponential backoff used for
// 429/503, since this is a brief backend blip, not sustained throttling; a
// tenant hitting a longer-lived version of this issue (confirmed live: it
// can persist for several minutes on one specific resource) will still see
// the error surface after these retries, with the message clarified by
// describeTransientTokenLifetimeError at the call site.

export interface GraphFetchOptions {
  maxRetries?: number;
  // POST/PATCH/DELETE calls that create or mutate state should NOT retry on a raw
  // network exception (fetch throwing) - the request may have already reached the
  // server and been processed; retrying could double it. A 429/503 HTTP response is
  // always safe to retry regardless, since the server is explicitly saying it did
  // not process the request. GET calls are naturally safe to retry either way.
  retryOnNetworkError?: boolean;
  onRetry?: (attempt: number, delayMs: number, reason: string) => void;
  // Per-attempt timeout. A hung request otherwise blocks forever, stalling the
  // whole sync (and, for the scheduler, every subsequent tenant in its pass).
  timeoutMs?: number;
}

const DEFAULT_MAX_RETRIES = 4;
const BASE_DELAY_MS = 500;
const MAX_DELAY_MS = 30_000;
const DEFAULT_TIMEOUT_MS = 30_000;
const LIFETIME_ERROR_MAX_RETRIES = 2;
const LIFETIME_ERROR_RETRY_DELAY_MS = 1500;

function isTransientLifetimeError(message: string | undefined): boolean {
  return !!message && /lifetime validation failed/i.test(message);
}

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
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  for (let attempt = 0, lifetimeErrorAttempt = 0; ; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: controller.signal, cache: "no-store" });
      const isThrottled = res.status === 429 || res.status === 503;
      if (isThrottled && attempt < maxRetries) {
        const retryAfterMs = parseRetryAfterMs(res.headers.get("Retry-After"));
        const delayMs = retryAfterMs ?? computeBackoffDelay(attempt);
        opts.onRetry?.(attempt + 1, delayMs, `HTTP ${res.status}`);
        await sleep(delayMs);
        continue;
      }
      if (res.status === 401 && lifetimeErrorAttempt < LIFETIME_ERROR_MAX_RETRIES) {
        // Peek the body via a clone so the original response is still fully
        // readable by the caller below - checking for this one specific
        // message must never consume the response callers expect to parse.
        const bodyText = await res
          .clone()
          .text()
          .catch(() => undefined);
        if (isTransientLifetimeError(bodyText)) {
          lifetimeErrorAttempt++;
          opts.onRetry?.(lifetimeErrorAttempt, LIFETIME_ERROR_RETRY_DELAY_MS, "Lifetime validation failed");
          await sleep(LIFETIME_ERROR_RETRY_DELAY_MS);
          continue;
        }
      }
      return res;
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === "AbortError";
      const reason = isTimeout ? `timeout after ${timeoutMs}ms` : err instanceof Error ? err.message : "network error";
      if (!retryOnNetworkError || attempt >= maxRetries) {
        throw isTimeout ? new Error(`Request timed out: ${reason}`) : err;
      }
      const delayMs = computeBackoffDelay(attempt);
      opts.onRetry?.(attempt + 1, delayMs, reason);
      await sleep(delayMs);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
