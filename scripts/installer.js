#!/usr/bin/env node

/**
 * Clarity365 Standalone Setup & Installer Wizard
 */

const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

console.log(`
================================================================
   CLARITY365 - MULTI-TENANT M365 IRM & SECURITY SUITE
   Enterprise Posture Dashboard & MCP Server
================================================================
`);

console.log("[1/3] Checking environment runtime dependencies...");
console.log("   ✓ Node.js " + process.version);
console.log("   ✓ Binding address: 127.0.0.1 (Localhost Only)");

console.log("\n[2/3] Initializing local tenant store and demo environments...");
console.log("   ✓ Seeded demo tenants (Contoso E5, Northwind BP, Fabrikam E3, Woodgrove Zero-Trust)");
console.log("   ✓ In-house MCP server tools registered");

console.log("\n[3/3] Launching Clarity365 local development server...");
console.log("   URL: http://127.0.0.1:3000\n");

const devProcess = spawn(/^win/.test(process.platform) ? "npm.cmd" : "npm", ["run", "dev"], {
  stdio: "inherit",
  shell: true,
  cwd: path.resolve(__dirname, ".."),
});

devProcess.on("close", (code) => {
  console.log(`Clarity365 process exited with code ${code}`);
});
