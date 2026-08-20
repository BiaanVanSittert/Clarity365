import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        border: "var(--border)",
        panel: "var(--panel)",
        "panel-header": "var(--panel-header)",
        "traffic-pass-bg": "#ECFDF5",
        "traffic-pass-border": "#10B981",
        "traffic-pass-text": "#065F46",
        "traffic-warn-bg": "#FFFBEB",
        "traffic-warn-border": "#F59E0B",
        "traffic-warn-text": "#92400E",
        "traffic-fail-bg": "#FEF2F2",
        "traffic-fail-border": "#EF4444",
        "traffic-fail-text": "#991B1B",
        "traffic-info-bg": "#F8FAFC",
        "traffic-info-border": "#CBD5E1",
        "traffic-info-text": "#334155",
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["IBM Plex Mono", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      borderRadius: {
        sm: "2px",
        DEFAULT: "4px",
        md: "6px",
      },
    },
  },
  plugins: [],
};
export default config;
