// Local Node/CLI qualification only. No browser, native app, service or deployment claim.
import {mkdir,readFile,writeFile,cp,symlink,realpath} from 'node:fs/promises';
import {resolve,dirname,join,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {generateKeyPairSync,createHash,privateDecrypt,constants,createDecipheriv} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {parseVectorInput,loadPinnedJose,encryptVector} from './generate_destination_vector.mjs';

async function main(){
 const [dependencyArg,outputArg]=process.argv.slice(2);assert.ok(dependencyArg&&outputArg);
 const dependency=await realpath(resolve(dependencyArg)),repo=await realpath(fileURLToPath(new URL('../../',import.meta.url)));
 const output=join(await realpath(dirname(resolve(outputArg))),resolve(outputArg).split(sep).at(-1));
 for(const p of [dependency,output])assert.ok(p!==repo&&!p.startsWith(repo+sep));
 await mkdir(output,{mode:0o700});
 const put=(name,value)=>writeFile(join(output,name),value,{mode:0o600,flag:'wx'});
 const jose=await loadPinnedJose(dependency),generator=fileURLToPath(new URL('./generate_destination_vector.mjs',import.meta.url));
 const key=generateKeyPairSync('rsa',{modulusLength:2048,publicExponent:65537});
 const {kty,n,e}=key.publicKey.export({format:'jwk'}),jwk={kty,n,e};
 const thumbprint=await jose.calculateJwkThumbprint(jwk,'sha256');
 const input={jwk,thumbprint,plaintext:{v:'djc-rendezvous/1',transaction_id:'dd11aa22-3344-4556-8abc-0123456789ab',generation:3,browser_key_thumbprint:thumbprint,expires_at:Date.now()+120000,bootstrap_origin:'https://vibecast.tv',display_entry_url:'https://ha.example.org/djconnect/vibecast/display',issuer_epoch:Buffer.alloc(32).toString('base64url')}};
 const encoded=value=>Buffer.from(JSON.stringify(value)),copy=()=>structuredClone(input),cases=[];
 async function test(name,run){try{await run();cases.push({name,status:'passed'});}catch(error){cases.push({name,status:'failed'});await put('failure-'+cases.length+'-private.log',String(error.stack??error));}}
 const invoke=(raw,args=[dependency])=>spawnSync(process.execPath,[generator,...args],{input:raw,encoding:'utf8',timeout:5000,maxBuffer:65536});
 function decryptNode(token){
  const parts=token.split('.').map(v=>Buffer.from(v,'base64url'));assert.equal(parts.length,5);assert.equal(parts[1].length,256);assert.equal(parts[2].length,12);assert.equal(parts[4].length,16);
  const cek=privateDecrypt({key:key.privateKey,padding:constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha256'},parts[1]);assert.equal(cek.length,32);
  const decipher=createDecipheriv('aes-256-gcm',cek,parts[2]);decipher.setAAD(Buffer.from(token.split('.')[0],'ascii'));decipher.setAuthTag(parts[4]);
  return Buffer.concat([decipher.update(parts[3]),decipher.final()]);
 }
 let first;
 await test('CLI compact envelope decrypts via standard Node RSA-OAEP256/AES256GCM APIs',async()=>{
  const r=invoke(encoded(input));assert.equal(r.status,0);assert.equal(r.stderr,'');assert.match(r.stdout,/^[A-Za-z0-9_.-]+\n$/);first=r.stdout.trim();
  assert.equal(first.length<=8192,true);assert.deepEqual(JSON.parse(decryptNode(first)),input.plaintext);
  const h=JSON.parse(Buffer.from(first.split('.')[0],'base64url'));assert.deepEqual(h,{alg:'RSA-OAEP-256',enc:'A256GCM',typ:'djc-rendezvous-destination+jwe',kid:thumbprint});
 });
 await test('jose decrypts CLI output to exact plaintext bytes',async()=>{const result=await jose.compactDecrypt(first,key.privateKey,{keyManagementAlgorithms:['RSA-OAEP-256'],contentEncryptionAlgorithms:['A256GCM']});assert.deepEqual(Buffer.from(result.plaintext),encoded(input.plaintext));});
 await test('RFC7638 thumbprint matches separate Node SHA256 canonical public tuple',async()=>{assert.equal(thumbprint,createHash('sha256').update(JSON.stringify({e,kty,n})).digest('base64url'));});
 await test('repeated public input gets library-managed fresh ciphertext and IV',async()=>{const r=invoke(encoded(input));assert.equal(r.status,0);const second=r.stdout.trim();assert.notEqual(second,first);assert.notEqual(second.split('.')[2],first.split('.')[2]);assert.deepEqual(JSON.parse(decryptNode(second)),input.plaintext);});
 await test('one optional final LF accepted',async()=>{assert.equal(invoke(Buffer.concat([encoded(input),Buffer.from('\n')])).status,0);});
 await test('past synthetic expiry remains expressible for consumer denial tests',async()=>{const v=copy();v.plaintext.expires_at=1;const r=invoke(encoded(v));assert.equal(r.status,0);assert.equal(JSON.parse(decryptNode(r.stdout.trim())).expires_at,1);});
 for(const index of [0,1,2,3,4])await test('altered compact segment '+index+' fails authenticated decryption',async()=>{const parts=first.split('.'),bytes=Buffer.from(parts[index],'base64url');bytes[Math.floor(bytes.length/2)]^=1;parts[index]=bytes.toString('base64url');await assert.rejects(()=>jose.compactDecrypt(parts.join('.'),key.privateKey,{keyManagementAlgorithms:['RSA-OAEP-256'],contentEncryptionAlgorithms:['A256GCM']}));});
 await test('different software recipient cannot decrypt',async()=>{const wrong=generateKeyPairSync('rsa',{modulusLength:2048});await assert.rejects(()=>jose.compactDecrypt(first,wrong.privateKey));});
 const mutations=[
  ['private-key-field',v=>{v.jwk.d='test-only-placeholder';}],['extra-jwk-alg',v=>{v.jwk.alg='RSA-OAEP-256';}],['wrong-exponent',v=>{v.jwk.e='Aw';}],
  ['padded-modulus',v=>{v.jwk.n+='=';}],['leading-zero-modulus',v=>{v.jwk.n=Buffer.concat([Buffer.from([0]),Buffer.from(n,'base64url')]).toString('base64url');}],
  ['wrong-modulus-bitlength',v=>{const b=Buffer.from(n,'base64url');b[0]&=127;v.jwk.n=b.toString('base64url');}],['even-modulus',v=>{const b=Buffer.from(n,'base64url');b[255]&=254;v.jwk.n=b.toString('base64url');}],
  ['mismatched-thumbprint',v=>{v.thumbprint=Buffer.alloc(32,1).toString('base64url');v.plaintext.browser_key_thumbprint=v.thumbprint;}],['mismatched-plaintext-thumbprint',v=>{v.plaintext.browser_key_thumbprint=Buffer.alloc(32,1).toString('base64url');}],
  ['extra-request-field',v=>{v.extra=true;}],['credential-payload-field',v=>{v.plaintext.authorization='synthetic-placeholder';}],['wrong-protocol',v=>{v.plaintext.v='other';}],['wrong-origin',v=>{v.plaintext.bootstrap_origin='https://foreign.example';}],
  ['fractional-generation',v=>{v.plaintext.generation=1.5;}],['invalid-uuid-variant',v=>{v.plaintext.transaction_id='dd11aa22-3344-4556-7abc-0123456789ab';}],['unsafe-expiry-number',v=>{v.plaintext.expires_at=Number.MAX_SAFE_INTEGER+1;}],['padded-epoch',v=>{v.plaintext.issuer_epoch+='=';}]
 ];
 for(const url of ['http://ha.example.org/djconnect/vibecast/display','https://real-customer.invalid/djconnect/vibecast/display','https://ha.example.org.evil/djconnect/vibecast/display','https://127.0.0.1/djconnect/vibecast/display','https://ha.example.org:443/djconnect/vibecast/display','https://u@ha.example.org/djconnect/vibecast/display','https://ha.example.org/djconnect/vibecast/display?x=1','https://ha.example.org/djconnect/vibecast/display#x','https://xn--test.example.org/djconnect/vibecast/display','https://ha.example.org/djconnect/vibecast/%64isplay','https://ha.example.org/djconnect/vibecast/display/'])mutations.push(['unsafe-or-nonexample-destination-'+mutations.length,v=>{v.plaintext.display_entry_url=url;}]);
 for(const [name,change]of mutations)await test('CLI rejects '+name+' without echo',async()=>{const v=copy();change(v);const r=invoke(encoded(v));assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'vector_generation_rejected\n');});
 const invalidRaw=[['duplicate-request-key','{"thumbprint":"duplicate",'+JSON.stringify(input).slice(1)],['duplicate-jwk-key',JSON.stringify(input).replace('"kty":"RSA"','"kty":"RSA","kty":"RSA"')],['duplicate-plaintext-key',JSON.stringify(input).replace('"generation":3','"generation":3,"generation":3')],['pretty-cli-input',JSON.stringify(input,null,2)],['trailing-json',JSON.stringify(input)+'{}'],['too-large-input',' '.repeat(16385)],['invalid-utf8',Buffer.from([0xff])]];
 for(const [name,raw]of invalidRaw)await test('CLI denies framing '+name,async()=>{if(name.startsWith('duplicate-'))assert.doesNotThrow(()=>JSON.parse(raw));const r=invoke(raw);assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'vector_generation_rejected\n');});
 await test('wrong argument count is generic denial',async()=>{const r=invoke(encoded(input),[]);assert.equal(r.status,1);assert.equal(r.stdout,'');assert.equal(r.stderr,'vector_generation_rejected\n');});
 await test('module encryption performs no outbound fetch',async()=>{const original=globalThis.fetch;globalThis.fetch=()=>{throw new Error('network_forbidden');};try{await encryptVector(parseVectorInput(encoded(input)),jose);}finally{globalThis.fetch=original;}});
 const corrupt=join(output,'corrupt-package');await cp(dependency,corrupt,{recursive:true});
 await test('changed dependency code rejected before import',async()=>{await writeFile(join(corrupt,'dist/webapi/index.js'),'throw new Error("must_not_import");');await assert.rejects(()=>loadPinnedJose(corrupt),/vector_generation_rejected/);});
 const extra=join(output,'extra-package');await cp(dependency,extra,{recursive:true});await writeFile(join(extra,'unexpected.js'),'');
 await test('unexpected dependency file rejected',async()=>{await assert.rejects(()=>loadPinnedJose(extra),/vector_generation_rejected/);});
 const linked=join(output,'linked-package');await cp(dependency,linked,{recursive:true});await symlink(join(dependency,'README.md'),join(linked,'untrusted-link'));
 await test('dependency symlink rejected',async()=>{await assert.rejects(()=>loadPinnedJose(linked),/vector_generation_rejected/);});
 const sources={};for(const name of ['generate_destination_vector.mjs','run_jwe_vectors.mjs','jwe-dependency-provenance-v1.json'])sources[name]=createHash('sha256').update(await readFile(new URL('./'+name,import.meta.url))).digest('hex');
 const summary={scope:'SOFTWARE_ONLY_API_JWE_GENERATOR_NODE_CLI_NOT_BROWSER_NATIVE_OR_SERVICE_GO',node:process.version,jose:'6.2.12',tests_passed:cases.filter(v=>v.status==='passed').length,tests_failed:cases.filter(v=>v.status==='failed').length,cases,source_sha256:sources,private_material:'software RSA private keys process-memory only; not exported or persisted',not_run:['receiver crossrun of this API generator','native signed-iOS action binding','production JSON/URL parser qualification','AppAttest/HA/service/DO/E2E','deployment']};
 await put('summary-sanitized.json',JSON.stringify(summary,null,2)+'\n');
 assert.equal(summary.tests_failed,0);console.log('PASS: '+summary.tests_passed+' API software-only JWE generator cases; no service GO.');
}
main().catch(()=>{console.error('JWE generator qualification failed; diagnostics remain private.');process.exitCode=1;});
