#!/usr/bin/env node

/**
 * Clarity365 Process Stop Utility
 * Frees port 3000 and 8365 on Windows / macOS / Linux cleanly.
 *
 * Tries a graceful stop first (SIGTERM on POSIX, `taskkill` without /F on
 * Windows) so the server's own shutdown handlers (e.g. closing the SQLite
 * connection, see src/instrumentation.ts) get a chance to run, then falls
 * back to a force-kill after a short grace period for anything still alive.
 * Windows doesn't have real POSIX signal delivery, so the graceful step there
 * is best-effort insurance, not a guarantee - worst case it's identical to
 * the previous always-force behavior, plus a ~1.5s wait.
 */

const { execSync } = require("child_process");

console.log("[Clarity365] Stopping any running local dev / server processes on port 3000...");

function wait(ms) {
  try {
    if (process.platform === "win32") {
      execSync(`ping -n ${Math.max(1, Math.round(ms / 1000) + 1)} 127.0.0.1 >nul`, { stdio: "ignore" });
    } else {
      execSync(`sleep ${ms / 1000}`, { stdio: "ignore" });
    }
  } catch {}
}

function isRunningWindows(pid) {
  try {
    const output = execSync(`tasklist /FI "PID eq ${pid}"`, { encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] });
    return output.includes(String(pid));
  } catch {
    return false;
  }
}

function isRunningPosix(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

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
      if (pids.size === 0) return;

      for (const pid of pids) {
        try {
          execSync(`taskkill /PID ${pid}`, { stdio: "ignore" });
        } catch {}
      }
      wait(1500);
      for (const pid of pids) {
        if (isRunningWindows(pid)) {
          try {
            execSync(`taskkill /F /PID ${pid}`, { stdio: "ignore" });
          } catch {}
        }
        console.log(`   ✓ Terminated process PID ${pid} on port ${port}`);
      }
    } else {
      const output = execSync(`lsof -ti :${port}`, { encoding: "utf8", stdio: ["pipe", "pipe", "ignore"] }).trim();
      const pids = output.split("\n").filter(Boolean).map(Number);
      if (pids.length === 0) return;

      for (const pid of pids) {
        try {
          process.kill(pid, "SIGTERM");
        } catch {}
      }
      wait(1500);
      for (const pid of pids) {
        if (isRunningPosix(pid)) {
          try {
            process.kill(pid, "SIGKILL");
          } catch {}
        }
        console.log(`   ✓ Terminated process PID ${pid} on port ${port}`);
      }
    }
  } catch {
    // Port was already free
  }
}

killPort(3000);
killPort(8365);

console.log("[Clarity365] Port 3000 is now free and ready for 'npm run dev'.\n");
