// Actual two-origin loopback HTTP, never route interception or auth substitution.
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {writeFile} from 'node:fs/promises';
import {randomBytes} from 'node:crypto';
import {startRootIntegrationRuntime} from './root-integration-runtime.mjs';
import {privateDirectory} from './local-native-files.mjs';
import {verifyTools,moduleURL,toolsManifest} from './browser-interop-tools.mjs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';

const tools=process.argv[2];assert(tools,'prepared browser tools path required');
assert.equal(process.argv.length,3);
const toolsDir=await privateDirectory(tools,resolve(fileURLToPath(new URL('../..',import.meta.url))));
await verifyTools(toolsDir);
const {chromium,webkit}=await import(moduleURL(toolsDir,'playwright'));
const server=createServer((req,res)=>{
 if(req.url!=='/'||req.method!=='GET'){res.writeHead(404);res.end();return;}
 res.writeHead(200,{'Content-Type':'text/html','Cache-Control':'no-store','Referrer-Policy':'no-referrer'});res.end('<!doctype html><title>Local API transport qualification</title>');
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const origin='http://127.0.0.1:'+server.address().port;
let api;const cases=[];
try{
 api=await startRootIntegrationRuntime(origin);
 for(const [engine,type]of Object.entries({chromium,webkit})){
  const browser=await type.launch({headless:true});
  assert.equal(browser.version(),toolsManifest.engines[engine].version);
  try{
   const page=await browser.newPage();await page.goto(origin);await api.verify();
   const observations=await page.evaluate(async(base)=>{
    if(!isSecureContext||!crypto.subtle)throw Error('loopback_secure_context_required');
    const v='djc-rendezvous/1',encode=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
    const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},false,['encrypt','decrypt']);
    const full=await crypto.subtle.exportKey('jwk',pair.publicKey),claim=crypto.getRandomValues(new Uint8Array(32));
    const post=async(route,body)=>{const r=await fetch(base+route,{method:'POST',mode:'cors',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return {status:r.status,body:await r.json(),credentials:r.headers.get('Access-Control-Allow-Credentials')};};
    const created=await post('create',{v,generation:1,browser_public_key:{kty:'RSA',n:full.n,e:full.e},claim_commitment:encode(await crypto.subtle.digest('SHA-256',claim))});
    if(created.status!==201)throw Error('create_failed');
    const tx=created.body,binding={v,transaction_id:tx.transaction_id,generation:tx.generation,claim_secret:encode(claim)};
    const before=await post('poll',binding),early=await post('consume',binding),cancel=await post('cancel',binding),later=await post('consume',binding);
    const tampered=await post('cancel',{...binding,claim_secret:encode(new Uint8Array(32))});
    return {ttl:tx.expires_at-tx.created_at,qrMatches:tx.qr_payload.transaction_id===tx.transaction_id&&tx.qr_payload.expires_at===tx.expires_at&&tx.qr_payload.service_origin==='https://api.djconnect.dev',statuses:[before.status,early.status,cancel.status,later.status,tampered.status],pending:before.body.state,terminal:cancel.body.state,credentials:created.credentials};
   },api.base);
   assert.equal(observations.ttl,120000);assert(observations.qrMatches);assert.deepEqual(observations.statuses,[200,409,200,409,401]);assert.equal(observations.pending,'pending');assert.equal(observations.terminal,'cancelled');assert.equal(observations.credentials,null);
   cases.push({engine,scope:'REAL_BROWSER_HTTP_CREATE_POLL_CONSUME_DENIAL_CANCEL',...observations});
   await page.close();
  }finally{await browser.close();}
 }
 await api.verify();
 const post=(route,body,headers={})=>fetch(api.base+route,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body)});
 const keyId=randomBytes(32).toString('base64'),v='djc-rendezvous/1';
 const challenge=await post('attestation/challenge',{v,key_id:keyId,action:'register'});assert.equal(challenge.status,200);const first=await challenge.json();
 const malformed=await post('attestation/register',{v,key_id:keyId,challenge_id:first.challenge_id,attestation:'AA'});assert.equal(malformed.status,401);assert.deepEqual(await malformed.json(),{v,error:'invalid_sender_proof'});
 const retry=await post('attestation/challenge',{v,key_id:keyId,action:'register'});assert.deepEqual(await retry.json(),first);
 assert.equal((await post('create',{v},{Origin:'https://evil.example'})).status,403);
 assert.equal((await post('create',{v},{Origin:origin,Cookie:'synthetic-only'})).status,400);
 assert.equal((await fetch(api.base+'create',{method:'GET',headers:{Origin:origin}})).status,400);
 const big=await fetch(api.base+'create',{method:'POST',headers:{Origin:origin,'Content-Type':'application/json'},body:' '.repeat(16385)});assert.equal(big.status,413);
 const traces=await api.observations();assert(traces.filter(r=>r.method==='OPTIONS'&&r.status===204).length>=2);assert(traces.some(r=>r.method==='POST'&&r.route==='/create'&&r.status===201));
 await api.verify();const receipt={...api.receipt(),cases,trace:traces,genuine_malformed_registration:401,original_challenge_unchanged:true,real_preflight_count:traces.filter(r=>r.method==='OPTIONS').length,fixture_translation:'LOOPBACK_URL_AND_ORIGIN_TO_CANONICAL_REQUEST_WITH_FIXED_CF_METADATA; NOT_TLS_OR_EDGE_PROOF'};assert.equal(receipt.outbound,0);
 await verifyTools(toolsDir);
 if(process.env.DJC_ROOT_INTEGRATION_RECEIPT)await writeFile(process.env.DJC_ROOT_INTEGRATION_RECEIPT,JSON.stringify(receipt,null,2)+'\n',{mode:0o600});
 console.log(JSON.stringify({scope:receipt.scope,engines:cases.length,real_preflight_count:receipt.real_preflight_count,result:'PASS'}));
}finally{await api?.close();await new Promise(resolve=>server.close(resolve));}
