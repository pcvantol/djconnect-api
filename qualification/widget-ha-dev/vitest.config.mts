import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
	plugins: [cloudflareTest({ wrangler: { configPath: "./qualification/widget-ha-dev/wrangler.jsonc" } })],
	test: { include: ["qualification/widget-ha-dev/worker.case.ts"] },
});
