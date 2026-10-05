// One run per key at a time: a call made while a run for the same key is in
// progress gets that run's promise instead of starting a second one. Used by
// TenantStore.syncTenant so a tenant is never synced twice at once.
export function singleFlight<T>(inFlight: Map<string, Promise<T>>, key: string, start: () => Promise<T>): Promise<T> {
  const running = inFlight.get(key);
  if (running) return running;
  const run = start().finally(() => inFlight.delete(key));
  inFlight.set(key, run);
  return run;
}

// Waits for any run in progress for this key (ignoring how it ended), then
// starts - or joins - a fresh one. For work that must see a change made
// after the running one began.
export async function singleFlightAfterCurrent<T>(inFlight: Map<string, Promise<T>>, key: string, start: () => Promise<T>): Promise<T> {
  const running = inFlight.get(key);
  if (running) await running.catch(() => undefined);
  return singleFlight(inFlight, key, start);
}
