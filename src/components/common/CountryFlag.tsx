import React from "react";
import { Globe } from "lucide-react";
import { UNKNOWN_COUNTRY, getCountryDisplayName } from "@/lib/utils/sign-in-country";

interface CountryFlagProps {
  code: string;
  size?: number;
  className?: string;
}

// Single shared spot rendering a country's flag (via the flag-icons package -
// real SVG assets, no emoji) so every call site (chip bar, table, drawer,
// dashboard widget) stays visually and behaviorally consistent instead of
// each re-implementing the "unknown" fallback separately.
export const CountryFlag: React.FC<CountryFlagProps> = ({ code, size = 13, className = "" }) => {
  const normalized = (code || "").toLowerCase();

  if (normalized === UNKNOWN_COUNTRY || !/^[a-z]{2}$/.test(normalized)) {
    return <Globe size={size} className={`text-slate-400 dark:text-slate-500 shrink-0 ${className}`} aria-label="Unknown location" />;
  }

  return (
    <span
      className={`fi fi-${normalized} fis shrink-0 rounded-[1px] ${className}`}
      style={{ fontSize: size }}
      role="img"
      aria-label={getCountryDisplayName(normalized)}
    />
  );
};
