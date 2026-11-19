
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
export default defineConfig({ test: { include: ["qualification/watch-moment/private-binding/binding.case.ts"] }, plugins: [cloudflareTest({wrangler: {configPath: fileURLToPath(new URL("./wrangler.json", import.meta.url))}})] });
