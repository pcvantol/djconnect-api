import {defineConfig} from 'vitest/config';
import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
import {fileURLToPath} from 'node:url';
export default defineConfig({root:fileURLToPath(new URL('../../../',import.meta.url)),
  plugins:[cloudflareTest({wrangler:{configPath:fileURLToPath(new URL('../../worker-do/qualification/wrangler.jsonc',import.meta.url))}})],
  test:{include:['coordinator/installation-principal/qualification/codec.check.ts'],testTimeout:15000},
});
