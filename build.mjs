import { execSync } from "node:child_process";
import { cpSync, mkdirSync } from "node:fs";

mkdirSync("dist", { recursive: true });

execSync("go build ./...", { stdio: "inherit" });
execSync("npx tsc", { stdio: "inherit" });

const goroot = execSync("go env GOROOT").toString().trim();
cpSync(`${goroot}/lib/wasm/wasm_exec.js`, "dist/wasm_exec.js");

execSync("go build -o dist/widevine.wasm ./internal/wasm", {
  stdio: "inherit",
  env: { ...process.env, GOOS: "js", GOARCH: "wasm" },
});

console.log("built dist/");
