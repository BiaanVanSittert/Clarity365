// Follows @odata.nextLink to collect every page of a Graph list response, instead of
// silently truncating at whatever the first page's $top returned. Tracks partial
// failure (a later page erroring, or the safety cap being hit) so callers can surface
// "this data may be incomplete" instead of presenting a truncated result as complete.

import { graphFetch } from "./graph-fetch";

export interface PagedFetchResult<T = any> {
  items: T[];
  isPartial: boolean;
  error?: string;
}

const DEFAULT_MAX_PAGES = 50;

/**
 * Fetches all pages of a Graph list endpoint.
 *
 * `initialUrls` may be a single URL or an ordered list of candidate URLs for the
 * *first* request only (e.g. Graph rejecting a large $top with 400 on some tenant
 * configurations - retry the first page at a smaller size, then paginate normally
 * via @odata.nextLink from whichever candidate succeeded).
 */
export async function fetchAllPages<T = any>(
  initialUrls: string | string[],
  headers: HeadersInit,
  maxPages: number = DEFAULT_MAX_PAGES
): Promise<PagedFetchResult<T>> {
  const candidates = Array.isArray(initialUrls) ? initialUrls : [initialUrls];
  const items: T[] = [];
  let nextUrl: string | undefined;
  let firstPageOk = false;
  let lastError: string | undefined;

  for (const candidate of candidates) {
    try {
      const res = await graphFetch(candidate, { headers });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data.value)) items.push(...data.value);
        nextUrl = data["@odata.nextLink"];
        firstPageOk = true;
        break;
      }
      const errJson = await res.json().catch(() => ({}));
      lastError = errJson?.error?.message || `HTTP ${res.status} ${res.statusText}`;
    } catch (err: any) {
      lastError = err.message || "Network error";
    }
  }

  if (!firstPageOk) {
    return { items, isPartial: true, error: lastError || "Request failed." };
  }

  let pageCount = 1;
  while (nextUrl) {
    if (pageCount >= maxPages) {
      return {
        items,
        isPartial: true,
        error: `Stopped after ${maxPages} pages (safety cap) - more records may exist.`,
      };
    }
    try {
      const res = await graphFetch(nextUrl, { headers });
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        const message = errJson?.error?.message || `HTTP ${res.status} ${res.statusText}`;
        return { items, isPartial: true, error: `Pagination stopped early: ${message}` };
      }
      const data = await res.json();
      if (Array.isArray(data.value)) items.push(...data.value);
      nextUrl = data["@odata.nextLink"];
      pageCount++;
    } catch (err: any) {
      return { items, isPartial: true, error: `Pagination stopped early: ${err.message || "network error"}` };
    }
  }

  return { items, isPartial: false };
}
