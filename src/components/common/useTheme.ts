import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "clarity365_theme";

// The <html> element's "dark" class is applied synchronously before hydration
// by an inline script in layout.tsx (to avoid a flash of the wrong theme) -
// this hook just mirrors that class into React state so components (e.g. the
// toggle button's icon) can react to it, and persists changes on toggle.
export function useTheme() {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    setIsDark(document.documentElement.classList.contains("dark"));
  }, []);

  const toggleTheme = useCallback(() => {
    setIsDark((prev) => {
      const next = !prev;
      document.documentElement.classList.toggle("dark", next);
      try {
        localStorage.setItem(STORAGE_KEY, next ? "dark" : "light");
      } catch {
        // Ignore - theme just won't persist across reloads.
      }
      return next;
    });
  }, []);

  return { isDark, toggleTheme };
}
