import { spawn } from "node:child_process";

const timeoutMs = Number.parseInt(process.env.DEPS_REPORT_TIMEOUT_MS ?? "15000", 10);
const child = spawn("npm", ["outdated"], {
	stdio: "inherit",
	shell: process.platform === "win32",
});

const timer = setTimeout(() => {
	console.warn(`npm outdated did not finish within ${timeoutMs}ms; continuing because this is a freshness report.`);
	child.kill("SIGTERM");
}, timeoutMs);

child.on("exit", () => {
	clearTimeout(timer);
	process.exit(0);
});

child.on("error", (error) => {
	clearTimeout(timer);
	console.warn(`Unable to run npm outdated: ${error.message}`);
	process.exit(0);
});
