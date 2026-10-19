// Local real-product bundle/RPC qualification. Never uploads or enables the service.
import assert from 'node:assert/strict';
import {createHash,X509Certificate} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const load=async name=>JSON.parse(await readFile(join(repo,name),'utf8'));
let phase='prepare',output,runtime;

async function main(){
	output=await mkdtemp(join(tmpdir(),'djc-product-build-'));
	const inputs=await load('rendezvous-build-inputs.json');
	assert.deepEqual(Object.keys(inputs).sort(),['schema_version','scope','aliases','dependencies','root_exports','rpc_allowlists','anchor_der_sha256','public_activation_allowed','base_main_sha','base_wrangle_config_sha256','local_test_bindings','shared_scope'].sort());
	assert.equal(inputs.schema_version,1);
	assert.equal(inputs.scope,'PRIVATE_COORDINATOR_BUILD_COMPILED_PUBLIC_UNAVAILABLE');
	assert.equal(inputs.public_activation_allowed,false);
	const trust=await readFile(join(repo,'src/rendezvous/trust.ts'),'utf8');
	for(const [name,file] of [['attestationRoot','apple-attestation-root.pem'],['receiptRoot','apple-receipt-root.cer']]){
		const literal=trust.match(new RegExp('export const '+name+' = Uint8Array.from\\(atob\\("([A-Za-z0-9+/=]+)"\\)'));
		assert.ok(literal);
		const der=Buffer.from(literal[1],'base64');
		assert.equal(sha(der),inputs.anchor_der_sha256[name]);
		assert.deepEqual(der,new X509Certificate(await readFile(join(repo,'qualification/rendezvous',file))).raw);
	}
	const aliases={
		'djc-existing-crypto':'./src/crypto.ts',
		'djc-qualified-assertion':'./qualification/rendezvous/app-attest-core-candidate.mjs',
		'djc-wire-schema':'./docs/rendezvous/wire-request-schemas-v1.json',
		'djc-enrollment-trust':'./src/rendezvous/trust.ts',
	};
	assert.deepEqual(inputs.aliases,aliases);
	const wrangler=await readFile(join(repo,'wrangler.jsonc'),'utf8');
	const block=wrangler.match(/\n\t"alias": (\{[^{}]*\}),/);
	assert.ok(block);
	assert.deepEqual(JSON.parse(block[1]),aliases);
	assert.equal(sha(wrangler.replace(block[0],'')),inputs.base_wrangle_config_sha256);
	const ts=await readFile(join(repo,'tsconfig.json'),'utf8');
	assert.deepEqual(JSON.parse(ts.match(/"paths"\s*:\s*(\{[^{}]*\})/)[1]),Object.fromEntries(Object.entries(aliases).map(([k,v])=>[k,[v]])));
	const vite=await readFile(join(repo,'vitest.config.mts'),'utf8');
	assert.ok(vite.includes('Object.entries(buildInputs.aliases)'));
	assert.ok(vite.includes('new URL(path, import.meta.url)'));
	const pkg=await load('package.json'),lock=await load('package-lock.json');
	assert.deepEqual(pkg.dependencies,inputs.dependencies);
	for(const [name,version] of Object.entries(inputs.dependencies))assert.equal(lock.packages['node_modules/'+name].version,version);
	for(const file of ['dependency-provenance-v1.json','core-dependency-provenance-v1.json']){
		const provenance=await load('qualification/rendezvous/'+file);
		for(const p of provenance.packages){
			assert.equal(lock.packages[p.path]?.version,p.version);
			assert.equal(lock.packages[p.path]?.integrity,p.integrity);
		}
	}
	const sources={};
	for(const file of ['src/index.ts','src/rendezvous/perimeter.ts','src/rendezvous/coordinators.ts','src/rendezvous/trust.ts','package.json','package-lock.json','wrangler.jsonc','tsconfig.json','vitest.config.mts','rendezvous-build-inputs.json','scripts/qualify_rendezvous_product_build.mjs'])sources[file]=sha(await readFile(join(repo,file)));
	phase='actual-product-dry-run';
	const built=spawnSync(process.execPath,[join(repo,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--outdir',output,'--metafile',join(output,'metafile.json')],{cwd:repo,encoding:'utf8'});
	await writeFile(join(output,'private-build.log'),built.stdout+built.stderr,{mode:0o600});
	assert.equal(built.status,0);
	const meta=JSON.parse(await readFile(join(output,'metafile.json'),'utf8'));
	const entry=Object.entries(meta.outputs).find(([name])=>name.endsWith('/index.js'));
	assert.ok(entry);
	assert.deepEqual(entry[1].exports.toSorted(),inputs.root_exports.toSorted());
	const virtualInputs={};
	for(const file of Object.keys(meta.inputs)){
		assert.ok(!/(?:-harness|\.check\.|fixtures|pre-qr-replacement-reference)/i.test(file),file);
		if(file==='node-built-in-modules:stream'||file==='node-built-in-modules:buffer'){
			assert.deepEqual(meta.inputs[file].imports,[{path:file.split(':')[1],kind:'import-statement',external:true}]);
			virtualInputs[file]=meta.inputs[file];
			continue;
		}
		const p=resolve(repo,file);
		assert.ok(p.startsWith(repo+'/'),file);
		sources[file]=sha(await readFile(p));
	}
	const bundle=await readFile(join(output,'index.js'),'utf8');
	for(const name of ['SoftwareEnrollment','SoftwareTransaction','createSoftwareStub','qualifySynthetic','SOFTWARE_STUB_COMPOSITION','djc-enrollment-fixtures'])assert.ok(!bundle.includes(name),name);
	assert.ok(bundle.includes('unavailableRendezvousResponse'));
	const classes=Object.values(inputs.local_test_bindings);
	// This driver is exclusively local QA, outside the product import graph.
	const driver=`import * as product from './bundle.mjs';
export {RequestAdmission,AllocationBudget,AllocationIndex,EnrollmentCoordinator,BudgetedTransactionCoordinator} from './bundle.mjs';
export default {async fetch(request,env,ctx){
 const url=new URL(request.url);
 if(url.pathname==='/__private_product_test/egress-guard')return fetch('https://egress-denied.example.invalid/qualification');
 if(url.pathname==='/__private_product_test/perimeter'){
  const probe=new Request('https://api.djconnect.dev/v1/rendezvous/create',{method:'POST',headers:{Origin:'https://vibecast.tv','X-Rendezvous-Enabled':'true'},body:'example-opaque-proof'});
  return product.default.fetch(probe,env,ctx);
 }
 if(url.pathname==='/__private_product_test/exports')return Response.json({exports:Object.keys(product).sort(),methods:Object.fromEntries(${JSON.stringify(classes)}.map(name=>[name,Object.getOwnPropertyNames(product[name].prototype).filter(n=>n!=='constructor').sort()]))});
 if(url.pathname==='/__private_product_test/rpc'){
  const body=await request.json();
  try{
   const stub=env[body.binding].get(env[body.binding].idFromName(body.name));
   if(body.read)return Response.json({value:await stub[body.method]});
   const args=body.args??[];
   if(body.method==='enroll'&&Array.isArray(args[0]?.attestation))args[0].attestation=new Uint8Array(args[0].attestation);
   return Response.json({value:await stub[body.method](...args)});
  }catch{return Response.json({rpc_rejected:true},{status:409});}
 }
 return product.default.fetch(request,env,ctx);
}};`;
	phase='local-real-bundle-rpc';
	// Resolve the already locked runtime through the declared Wrangler toolchain.
	const wranglerRequire=createRequire(import.meta.resolve('wrangler'));
	const {Miniflare,Log,LogLevel,convertV4MiniflareOptions}=wranglerRequire('miniflare');
	let egress=0;
	const configured={
		ALLOCATION_POLICY_ENABLED:'djc-allocation-qualification/1',
		INDEX_POLICY_ENABLED:'djc-index-qualification/1',
		REQUEST_POLICY_ENABLED:'djc-request-admission-qualification/2',
		COMPOSED_POLICY_ENABLED:'djc-http-composition-qualification/1',
		ASSERTION_POLICY_ENABLED:'ios-dev-qualification/1',
		ASSERTION_POLICY_EXPIRES_AT:String(Date.now()+1800000),
		ENROLLMENT_POLICY_REVISION:'local-product-build-negative-only',
		// Deterministic SYNTHETIC local material; never a deployment secret.
		RECEIPT_ACTIVE_KEY:Buffer.alloc(32,17).toString('base64'),
	};
	const options=name=>({name,compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],modulesRoot:output,
		outboundService:()=>{egress++;return new Response(null,{status:503});},
		modules:[{type:'ESModule',path:join(output,'driver.mjs'),contents:driver},{type:'ESModule',path:join(output,'bundle.mjs'),contents:bundle}],
		bindings:name==='configured'?configured:{},
		durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([name,className])=>[name,{className,useSQLite:true}])),
	});
	runtime=new Miniflare(convertV4MiniflareOptions({workers:[options('missing'),options('configured')],durableObjectsPersist:false,unsafeInspectDurableObjects:true,log:new Log(LogLevel.NONE)}));
	const missing=await runtime.getWorker('missing'),good=await runtime.getWorker('configured');
	assert.equal((await good.fetch('https://local.test/__private_product_test/egress-guard')).status,503);
	assert.equal(egress,1);egress=0;
	let checks=0,forbiddenCalls=0;
	const names={REQUEST_ADMISSION:'djc-rendezvous-requests/1',ADMISSION_STATE:'djc-rendezvous-budget/1',ALLOCATION_INDEX:'djc-rendezvous-index/1'};
	const rpc=async(worker,binding,method,args=[],read=false,name=names[binding]??'product-boundary-test')=>{
		const response=await worker.fetch('https://local.test/__private_product_test/rpc',{method:'POST',body:JSON.stringify({binding,method,args,read,name})});
		return {status:response.status,...await response.json()};
	};
	const manifest=await (await good.fetch('https://local.test/__private_product_test/exports')).json();
	assert.deepEqual(manifest.exports,inputs.root_exports.toSorted());checks++;
	for(const name of classes){assert.deepEqual(manifest.methods[name],inputs.rpc_allowlists[name].toSorted());checks++;}
	for(const worker of [missing,good]){
		// Miniflare's loopback Origin guard is separate from product CORS. The QA
		// driver constructs the exact Origin-bearing request inside the Worker.
		const response=await worker.fetch('https://local.test/__private_product_test/perimeter');
		assert.equal(response.status,503);assert.deepEqual(await response.json(),{v:'djc-rendezvous/1',error:'service_unavailable'});checks++;
	}
	const forbidden=['install','installInternal','evidence','advance','rotate','revoke','lookupSubmit','load','save','expire','debugState','state','engine','issue','getSql','verifyEnrollment'];
	for(const binding of Object.keys(inputs.local_test_bindings)){
		for(const method of forbidden){
			const result=await rpc(good,binding,method,[{example:'not-authority'}]);
			assert.equal(result.rpc_rejected,true,`${binding}:${method}`);forbiddenCalls++;checks++;
		}
		for(const method of ['env','ctx','state','engine']){
			const result=await rpc(good,binding,method,[],true);assert.equal(result.rpc_rejected,true,`${binding}:${method}:read`);forbiddenCalls++;checks++;
		}
	}
	const keyId=Buffer.alloc(32,7).toString('base64');
	const noConfig=await rpc(missing,'ENROLLMENT_COORDINATOR','issueEnrollment',[{keyId}]);
	assert.deepEqual(noConfig.value,{ok:false,error:'service_unavailable'});checks++;
	const absentProof=await rpc(missing,'ENROLLMENT_COORDINATOR','enroll',[{keyId,challengeId:Buffer.alloc(32,1).toString('base64url'),attestation:[0]}]);
	assert.deepEqual(absentProof.value,{ok:false,error:'service_unavailable'});checks++;
	const identity=()=>({minute:Math.floor(Date.now()/60000),key:Buffer.alloc(32,2).toString('base64url')});
	for(const [binding,method,args] of [
		['REQUEST_ADMISSION','admit',[{identity:identity(),lane:'poll'}]],
		['ADMISSION_STATE','admit',[{kind:'transaction',identity:identity()}]],
		['ALLOCATION_INDEX','allocate',[{identity:identity()}]],
	]){
		const result=await rpc(missing,binding,method,args);assert.deepEqual(result.value,{ok:false,error:'service_unavailable'});checks++;
		const wrongName=await rpc(good,binding,method,args,false,'wrong-object-name');assert.deepEqual(wrongName.value,{ok:false,error:'service_unavailable'});checks++;
		const configuredResult=await rpc(good,binding,method,args);
		assert.equal(configuredResult.value?.ok,true,`${binding}:configured`);checks++;
	}
	const challenge=await rpc(good,'ENROLLMENT_COORDINATOR','issueEnrollment',[{keyId}]);
	assert.equal(challenge.value?.ok,true);
	assert.equal(Buffer.from(challenge.value.challenge,'base64url').length,32);
	assert.ok(challenge.value.expires_at>Date.now()&&challenge.value.expires_at-Date.now()<=120000);checks++;
	const malformed=await rpc(good,'ENROLLMENT_COORDINATOR','enroll',[{keyId,challengeId:challenge.value.challenge_id,attestation:[0]}]);
	assert.deepEqual(malformed.value,{ok:false,error:'registration_rejected'});checks++;
	const retry=await rpc(good,'ENROLLMENT_COORDINATOR','issueEnrollment',[{keyId}]);
	assert.deepEqual(retry.value,challenge.value);checks++;
	const management=await rpc(good,'ENROLLMENT_COORDINATOR','issueAction',[{keyId,action:'recover-key'}]);
	assert.equal(management.value?.ok,true);checks++;
	const invalid=await rpc(good,'ENROLLMENT_COORDINATOR','authorize',[{operationId:management.value.challenge_id,action:'recover-key',clientData:management.value.client_data,assertion:Buffer.from([0]).toString('base64url')}]);
	assert.equal(invalid.value?.ok,false);checks++;
	// Host-side local read only: this is not a remotely exported storage seam.
	const enrollmentStorage=await runtime.unsafeGetDurableObjectStorage('configured','EnrollmentCoordinator',{name:'product-boundary-test'});
	assert.deepEqual(await enrollmentStorage.exec('SELECT COUNT(*) AS n FROM key_state'),[{n:0}]);checks++;
	const extra=await rpc(good,'ADMISSION_STATE','admitKeyCall',[1]);assert.deepEqual(extra.value,{ok:false,error:'service_unavailable'});checks++;
	const keyCall=await rpc(good,'ADMISSION_STATE','admitKeyCall');assert.deepEqual(keyCall.value,{ok:true});checks++;
	assert.equal(egress,0);checks++;
	await runtime.dispose();runtime=undefined;
	const report={schema_version:1,scope:'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY',result:'PASS',checks,forbidden_rpc_calls_rejected:forbiddenCalls,source_hashes:sources,
		toolchain:{node:process.version,wrangler:(await load('node_modules/wrangler/package.json')).version,miniflare:wranglerRequire('miniflare/package.json').version},
		bundle_sha256:sha(bundle),bundle_bytes:Buffer.byteLength(bundle),virtual_platform_inputs:virtualInputs,exports:entry[1].exports,rpc_allowlists:manifest.methods,
		default_no_config:'FAIL_CLOSED',configured_malformed_default_genuine_enrollment:'REJECTED_ORIGINAL_CHALLENGE_PRESERVED',configured_unknown_key_management_proof:'REJECTED',unauthorized_key_rows:0,outbound_calls:egress,
		compiled_public_disabled_with_or_without_private_test_configuration:true,root_binding_migration_mutations:false,native_positive_accepted:false,production_profile_accepted:false,service_activated:false,cloudflare_mutations:false};
	await writeFile(join(output,'observations.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
	console.log(`PASS: ${checks} actual product export/private-RPC/default-genuine-negative checks; ${forbiddenCalls} forbidden RPC calls rejected; no egress or activation. Evidence: ${output}`);
}

main().catch(async error=>{
	if(output)await writeFile(join(output,'private-error.log'),String(error.stack??error),{mode:0o600});
	console.error(`Product build qualification failed at ${phase}; private diagnostics: ${output??'unavailable'}`);
	process.exitCode=1;
}).finally(async()=>{if(runtime)try{await runtime.dispose();}catch{/* The original startup/test failure is already recorded. */}});
