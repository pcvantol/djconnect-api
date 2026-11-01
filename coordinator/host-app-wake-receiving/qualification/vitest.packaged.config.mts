import {defineConfig} from 'vitest/config';
import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
import {fileURLToPath} from 'node:url';
import {realpathSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {verifyPackage} from '../runtime/package-lib.mjs';
const value=process.env.DJC_HOST_WAKE_PACKAGE;if(!value)throw Error('explicit previously verified package directory required');
const artifact=realpathSync(value);await verifyPackage(artifact,process.env.DJC_HOST_WAKE_PACKAGE_PROOF);const entry=join(artifact,'receiving.mjs');if(!existsSync(entry))throw Error('package module missing');
export default defineConfig({root:fileURLToPath(new URL('../../../',import.meta.url)),
 resolve:{alias:[{find:'../service',replacement:entry},{find:'djc-shipped-receiving',replacement:entry}]},
 server:{fs:{allow:[fileURLToPath(new URL('../../../',import.meta.url)),artifact]}},
 plugins:[cloudflareTest({wrangler:{configPath:fileURLToPath(new URL('wrangler.jsonc',import.meta.url))}})],
 test:{include:['coordinator/host-app-wake-receiving/qualification/*.check.ts'],exclude:['coordinator/host-app-wake-receiving/qualification/enrollment-store.check.ts'],testTimeout:15000}});
