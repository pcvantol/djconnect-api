import { fileURLToPath } from "node:url";
import buildInputs from "./rendezvous-build-inputs.json" with { type: "json" };
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: { alias: Object.fromEntries(Object.entries(buildInputs.aliases).map(([name, path]) => [name, fileURLToPath(new URL(path, import.meta.url))])) },
	plugins: [
		cloudflareTest({
			wrangler: { configPath: "./wrangler.jsonc" },
		}),
	],
	test: {
	},
});
