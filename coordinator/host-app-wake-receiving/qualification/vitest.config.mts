import {defineConfig} from 'vitest/config';
import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
import {fileURLToPath} from 'node:url';
export default defineConfig({root:fileURLToPath(new URL('../../../',import.meta.url)),
 plugins:[cloudflareTest({wrangler:{configPath:fileURLToPath(new URL('wrangler.jsonc',import.meta.url))}})],
 test:{include:['coordinator/host-app-wake-receiving/qualification/*.check.ts'],exclude:['coordinator/host-app-wake-receiving/qualification/enrollment-store.check.ts'],testTimeout:15000}});
