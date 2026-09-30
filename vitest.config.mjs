import { defineConfig } from "vitest/config";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
  // tsconfig.json keeps "jsx": "preserve" for Next.js, which Vite can't
  // execute - compile JSX here so tests can import .tsx components (first
  // used by SignInSituationsModule.test.ts's server-render smoke test).
  // Vite 8 transforms with Oxc, not esbuild, so the option lives here.
  oxc: {
    jsx: { runtime: "automatic" },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
