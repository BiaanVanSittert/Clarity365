#!/usr/bin/env node

/**
 * Clarity365 Process Stop Utility
 * Frees port 3000 and 8365 on Windows / macOS / Linux cleanly.
 */

const { execSync } = require("child_process");

console.log("[Clarity365] Stopping any running local dev / server processes on port 3000...");

function killPort(port) {
  try {
    if (process.platform === "win32") {
      const output = execSync(`netstat -ano | findstr :${port}`, { encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] });
      const lines = output.trim().split("\n");
      const pids = new Set();
      for (const line of lines) {
        const parts = line.trim().split(/\s+/);
        if (parts.length >= 5) {
          const pid = parts[parts.length - 1];
          if (pid && pid !== "0" && !isNaN(parseInt(pid))) {
            pids.add(pid);
          }
        }
      }
      for (const pid of pids) {
        try {
          execSync(`taskkill /F /PID ${pid}`, { stdio: "ignore" });
          console.log(`   ✓ Terminated process PID ${pid} on port ${port}`);
        } catch {}
      }
    } else {
      execSync(`lsof -ti :${port} | xargs kill -9`, { stdio: "ignore" });
      console.log(`   ✓ Terminated process on port ${port}`);
    }
  } catch {
    // Port was already free
  }
}

killPort(3000);
killPort(8365);

console.log("[Clarity365] Port 3000 is now free and ready for 'npm run dev'.\n");
