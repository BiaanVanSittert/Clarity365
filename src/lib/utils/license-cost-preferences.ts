// Per-tenant, per-browser preference for which license SKUs the admin has
// chosen to exclude from License & Cost Optimizer's waste calculation, chart,
// and items table - the manual override for SKUs the automatic per-SKU cost
// table (license-sku-costs.ts) can't know about (an unrecognized $0
// self-service grant, or a SKU the admin simply doesn't want counted).
// Same localStorage-per-tenant-key convention as Sidebar.tsx's alert
// dismissal state - a display preference, not data worth persisting server-side.
const STORAGE_KEY_PREFIX = "clarity365_disabled_license_skus_";

export function getDisabledLicenseSkus(tenantId: string): Set<string> {
  try {
    const raw = localStorage.getItem(`${STORAGE_KEY_PREFIX}${tenantId}`);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw);
    return new Set(Array.isArray(parsed) ? parsed : []);
  } catch {
    return new Set();
  }
}

export function setLicenseSkuDisabled(tenantId: string, skuPartNumber: string, disabled: boolean): Set<string> {
  const current = getDisabledLicenseSkus(tenantId);
  if (disabled) current.add(skuPartNumber);
  else current.delete(skuPartNumber);
  try {
    localStorage.setItem(`${STORAGE_KEY_PREFIX}${tenantId}`, JSON.stringify(Array.from(current)));
  } catch {
    // localStorage unavailable (private browsing, quota, etc.) - the toggle
    // still works for the current page load, it just won't persist.
  }
  return current;
}
