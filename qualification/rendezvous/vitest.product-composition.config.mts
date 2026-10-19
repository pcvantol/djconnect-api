// Private local test configuration; never a deployment configuration.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {defineConfig} from 'vitest/config';
import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
import inputs from '../../rendezvous-build-inputs.json' with {type:'json'};
const repo=fileURLToPath(new URL('../../',import.meta.url));
export default defineConfig({
	root:repo,
	resolve:{alias:Object.fromEntries(Object.entries(inputs.aliases).map(([name,path])=>[name,resolve(repo,path)]))},
	plugins:[cloudflareTest({wrangler:{configPath:resolve(repo,'wrangler.jsonc')},miniflare:{
		durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([name,className])=>[name,{className,useSQLite:true}])),
		bindings:{
			RENDEZVOUS_EDGE_POLICY:'djc-direct-edge-identity/1-candidate',
			RENDEZVOUS_IP_HASH_KEY:Buffer.alloc(32,21).toString('base64'),
			RECEIPT_ACTIVE_KEY:Buffer.alloc(32,22).toString('base64'),
			COMPOSED_POLICY_ENABLED:'djc-http-composition-qualification/1',
			REQUEST_POLICY_ENABLED:'djc-request-admission-qualification/2',
			ALLOCATION_POLICY_ENABLED:'djc-allocation-qualification/1',
			INDEX_POLICY_ENABLED:'djc-index-qualification/1',
			ASSERTION_POLICY_ENABLED:'ios-dev-qualification/1',
			ASSERTION_POLICY_EXPIRES_AT:String(Date.now()+1800000),
			ENROLLMENT_POLICY_REVISION:'local-product-module-only',
		},
	}})],
	test:{include:['qualification/rendezvous/product-composition.check.ts'],testTimeout:20000},
});
