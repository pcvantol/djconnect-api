import {defineConfig} from 'vitest/config';
import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
import {fileURLToPath} from 'node:url';
import inputs from '../../../../rendezvous-build-inputs.json' with {type:'json'};
const root=fileURLToPath(new URL('../../../../',import.meta.url));
export default defineConfig({root,resolve:{alias:Object.fromEntries(Object.entries(inputs.aliases).map(([k,v])=>[k,fileURLToPath(new URL('../../../../'+v,import.meta.url))]))},plugins:[cloudflareTest({wrangler:{configPath:fileURLToPath(new URL('./wrangler.jsonc',import.meta.url))}})],test:{include:['coordinator/host-app-wake-receiving/qualification/production/*.check.ts'],testTimeout:15000}});
