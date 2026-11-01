import {readFile,readdir,lstat,realpath} from 'node:fs/promises';
import {resolve,relative,isAbsolute,sep,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
export const dir=dirname(fileURLToPath(import.meta.url)),root=resolve(dir,'../../..');
export const sha=b=>createHash('sha256').update(b).digest('hex');
export const load=async p=>JSON.parse(await readFile(p,'utf8'));
export const sqlText=text=>text.replace(/--[^\n]*/g,'').trim().replace(/CREATE (VIEW|TRIGGER) IF NOT EXISTS/g,'CREATE $1').replace(/\s+/g,' ').replace(/;$/,'').trim();
export const canonical=o=>JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a],[b])=>a.localeCompare(b))));
export async function files(base,prefix=''){let out=[];for(const e of await readdir(join(base,prefix),{withFileTypes:true})){const p=join(prefix,e.name),s=await lstat(join(base,p));assert.ok(!s.isSymbolicLink(),'symlink '+p);if(s.isDirectory())out.push(...await files(base,p));else{assert.ok(s.isFile());out.push(p.split(sep).join('/'));}}return out.sort();}
export async function inputs(policy){
 const safe=p=>typeof p==='string'&&p.length>0&&!isAbsolute(p)&&!p.includes('\\')&&!p.includes(':')&&!p.split('/').includes('..');for(const p of [...Object.keys(policy.inputs_sha256),...policy.deliverables,...Object.keys(policy.copies),...Object.values(policy.copies)])assert.ok(safe(p),'unsafe package path');
 const bundled=[...new Set(policy.graph_inputs.filter(p=>p.startsWith('node_modules/')).map(p=>{const a=p.slice(13).split('/');return a[0].startsWith('@')?a.slice(0,2).join('/'):a[0];}))].sort();assert.deepEqual(bundled,Object.keys(policy.packages).sort());for(const p of bundled)assert.ok(Object.values(policy.copies).some(x=>x.startsWith('node_modules/'+p+'/LICENSE')),'bundled license '+p);
 for(const [path,hash] of Object.entries(policy.inputs_sha256))assert.equal(sha(await readFile(join(root,path))),hash,'source/installed drift '+path);
 const lock=await load(join(root,'package-lock.json'));
 for(const [name,expected] of Object.entries(policy.packages)){const p='node_modules/'+name;assert.equal((await load(join(root,p,'package.json'))).version,expected.version);assert.equal(lock.packages[p].version,expected.version);assert.equal(lock.packages[p].integrity,expected.integrity);}
 const config=await load(join(dir,'wrangler.jsonc'));assert.deepEqual(config.compatibility_flags,['nodejs_compat']);assert.equal(config.compatibility_date,'2026-08-22');assert.deepEqual(policy.compatibility,{date:config.compatibility_date,flags:config.compatibility_flags});assert.equal(config.workers_dev,false);assert.ok(!config.routes&&!config.vars&&!config.d1_databases&&!config.account_id);
 const guard=await readFile(join(root,'coordinator/host-app-wake-receiving/guard-schema.ts'),'utf8'),codePins=JSON.parse(guard.match(/const expected = (\{[^\n]+\}) as const/)[1]);assert.deepEqual(Object.keys(policy.sql_objects).sort(),Object.keys(codePins).sort());for(const [name,item]of Object.entries(policy.sql_objects)){assert.equal(item.sha256,codePins[name]);assert.equal(sha(Buffer.from(sqlText(await readFile(join(root,policy.copies[item.file]),'utf8')))),item.sha256,'SQL code pin '+name);}
 const helper=await readFile(join(root,'coordinator/host-app-wake-receiving/native-apple-evidence.mjs'),'utf8');assert.ok(helper.includes("import {prepareCommonStatusRequest,qualifyCommonStatus} from '../../qualification/rendezvous/receipt-status-candidate.mjs';"));
}
/** The externally retained proof digest is mandatory: self-authored JSON is
 * not an authenticity root. This checker does not confer service authority. */
export async function verifyPackage(base,expectedProof){
 assert.match(expectedProof??'',/^[a-f0-9]{64}$/,'trusted package proof digest required');base=await realpath(base);
 const raw=await readFile(join(base,'package-proof.json'));assert.equal(sha(raw),expectedProof,'package proof root');const proof=JSON.parse(raw),policy=await load(join(dir,'source-inputs.json'));await inputs(policy);
 assert.equal(proof.classification,'PRIVATE_RECEIVING_SOURCE_DISTRIBUTION_NOT_RUNTIME_ADMISSION');assert.equal(proof.source_manifest_sha256,sha(await readFile(join(dir,'source-inputs.json'))));
 assert.deepEqual(await files(base),[...policy.deliverables,'package-proof.json'].sort());assert.deepEqual(Object.keys(proof.files_sha256).sort(),policy.deliverables);
 for(const [p,h] of Object.entries(proof.files_sha256))assert.equal(sha(await readFile(join(base,p))),h,'package file '+p);
 assert.equal(sha(await readFile(join(base,'SOURCE_MANIFEST.json'))),proof.source_manifest_sha256);
 for(const [dest,source]of Object.entries(policy.copies))assert.equal(proof.files_sha256[dest],policy.inputs_sha256[source],'copied source pin '+dest);
 for(const [name,item]of Object.entries(policy.sql_objects))assert.equal(sha(Buffer.from(sqlText(await readFile(join(base,item.file),'utf8')))),item.sha256,'packaged SQL pin '+name);
 const meta=await load(join(base,'metafile.json'));assert.deepEqual(Object.keys(meta.inputs).sort(),policy.graph_inputs);assert.deepEqual(meta.compatibility,policy.compatibility);assert.deepEqual(meta.selected_production_functions,policy.selected_production_functions);assert.deepEqual(meta.exports,['createReceivingService','default']);assert.deepEqual(meta.runtime_imports,['buffer','stream']);assert.deepEqual(meta.virtual_inputs,['node-built-in-modules:buffer','node-built-in-modules:stream']);
 for(const [name,value] of Object.entries(meta.inputs)){if(name.startsWith('node-built-in-modules:'))continue;assert.equal(value.sha256,policy.inputs_sha256[name],'metafile input '+name);}
 for(const p of ['metafile.json','package-proof.json','SOURCE_MANIFEST.json','receiving.mjs']){const text=await readFile(join(base,p),'utf8');assert.ok(!text.includes(root)&&!text.includes('/Volumes/')&&!text.includes('/Users/'),'host path '+p);}
 assert.equal(proof.public_activation,false);assert.equal(proof.genuine_native_qualification,false);return proof;
}
