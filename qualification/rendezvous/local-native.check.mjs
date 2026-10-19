import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,chmod,writeFile,readFile,symlink,link,rm,stat,mkdir,rename} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {privateDirectory,readPrivate,writePrivate,parseRequest,decode64,CommandBudget} from './local-native-files.mjs';
import {allowedStatusRequest,statusOnlyOutbound} from './local-native-egress.mjs';
import {startLocalRuntime,checkSourcePins,gitRead,repo} from './local-native-runtime.mjs';
import {processRequest} from './run-local-native.mjs';

const V='djc-rendezvous/1';
const encoded=(route,body)=>Buffer.from(JSON.stringify({route,body_base64url:Buffer.from(JSON.stringify(body)).toString('base64url')}));
async function privateTest(run){const path=await mkdtemp(join(tmpdir(),'djc-native-files-'));await chmod(path,0o700);try{await run(await privateDirectory(path,repo));}finally{await rm(path,{recursive:true,force:true});}}

test('host private directory rejects public modes, repository paths and symlink aliases',async()=>privateTest(async dir=>{
 await chmod(dir.path,0o755);await assert.rejects(privateDirectory(dir.path,repo));await chmod(dir.path,0o700);
 await assert.rejects(privateDirectory(repo,repo));
 const alias=dir.path+'-alias';await symlink(dir.path,alias);try{await assert.rejects(privateDirectory(alias,repo));}finally{await rm(alias);}
}));
test('descriptor-based reads reject missing, permissive, linked, special, empty and oversized inputs',async()=>privateTest(async dir=>{
 await assert.rejects(readPrivate(dir,'request.json'));
 await writeFile(join(dir.path,'target'), 'private',{mode:0o600});
 await symlink('target',join(dir.path,'request.json'));await assert.rejects(readPrivate(dir,'request.json'));await rm(join(dir.path,'request.json'));
 await link(join(dir.path,'target'),join(dir.path,'request.json'));await assert.rejects(readPrivate(dir,'request.json'));await rm(join(dir.path,'request.json'));
 await writeFile(join(dir.path,'request.json'),'x',{mode:0o644});await assert.rejects(readPrivate(dir,'request.json'));await chmod(join(dir.path,'request.json'),0o600);
 await writeFile(join(dir.path,'request.json'),'');await assert.rejects(readPrivate(dir,'request.json'));
 await writeFile(join(dir.path,'request.json'),Buffer.alloc(102401));await assert.rejects(readPrivate(dir,'request.json'));
 await rm(join(dir.path,'request.json'));await mkdir(join(dir.path,'request.json'),{mode:0o600});await assert.rejects(readPrivate(dir,'request.json'));await rm(join(dir.path,'request.json'),{recursive:true});
 const fifo=spawnSync('mkfifo',['-m','600',join(dir.path,'request.json')]);assert.equal(fifo.status,0);await assert.rejects(readPrivate(dir,'request.json'));
}));
test('outputs are exclusive/private, traversal and directory replacement fail',async()=>privateTest(async dir=>{
 await writePrivate(dir,'01-nonce.bin',Buffer.alloc(32,7));assert.equal((await stat(join(dir.path,'01-nonce.bin'))).mode&0o777,0o600);
 await assert.rejects(writePrivate(dir,'01-nonce.bin','overwrite'));await assert.rejects(writePrivate(dir,'../escape','x'));
 const old=dir.path+'-old';await rename(dir.path,old);await mkdir(dir.path,{mode:0o700});try{await assert.rejects(writePrivate(dir,'replaced','x'));}finally{await rm(dir.path,{recursive:true});await rename(old,dir.path);}
}));
test('closed canonical envelope preserves wire bytes; malformed/duplicate keys/base64/routes reject',()=>{
 const raw=Buffer.from('{"v":"djc-rendezvous/1","v":"duplicate"}');
 const envelope=Buffer.from(JSON.stringify({route:'/attestation/register',body_base64url:raw.toString('base64url')}));assert.deepEqual(parseRequest(envelope).body,raw);
 for(const value of [Buffer.from('{}'),Buffer.from('{"route":"/poll","route":"/cancel","body_base64url":"e30"}'),Buffer.from('{"route":"/poll","body_base64url":"e30","host":"evil"}'),Buffer.from('{"route":"/unknown","body_base64url":"e30"}'),Buffer.from('{"route":"/poll","body_base64url":"e30="}'),Buffer.from(' {"route":"/poll","body_base64url":"e30"}')])assert.throws(()=>parseRequest(value));
 for(const s of ['','A','/w','Zh','Zg='])assert.throws(()=>decode64(s));
});
test('finite command admission: sixteen only, expired/backward clocks fail without retry',()=>{
 const budget=new CommandBudget();for(let i=1;i<=16;i++)assert.equal(budget.take(),i);assert.throws(()=>budget.take());
 const now=Date.now,original=now(),b=new CommandBudget();try{Date.now=()=>original+900001;assert.throws(()=>b.take());Date.now=()=>original-100;assert.throws(()=>b.take());}finally{Date.now=now;}
});
test('source fingerprint guard rejects changed or missing bytes and escaping paths',async()=>privateTest(async dir=>{
 await writePrivate(dir,'source.mjs','original');const pins={'source.mjs':createHash('sha256').update('original').digest('hex')};
 await checkSourcePins(pins,dir.path);await writeFile(join(dir.path,'source.mjs'),'changed');await assert.rejects(checkSourcePins(pins,dir.path));
 await rm(join(dir.path,'source.mjs'));await assert.rejects(checkSourcePins(pins,dir.path));await assert.rejects(checkSourcePins({'../escape':'x'},dir.path));
}));
test('Git readback ignores inherited repository/config overrides and stays offline',async()=>privateTest(async dir=>{
 const baseline=gitRead(['rev-parse','HEAD']);assert.equal(baseline.status,0);
 assert.equal(spawnSync('git',['init','--quiet',dir.path]).status,0);
 const values={GIT_DIR:join(dir.path,'.git'),GIT_WORK_TREE:dir.path,GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'core.bare',GIT_CONFIG_VALUE_0:'true',GIT_NO_LAZY_FETCH:'0',GIT_TERMINAL_PROMPT:'1',GIT_OPTIONAL_LOCKS:'1',GIT_NO_REPLACE_OBJECTS:'0'};
 const original=Object.fromEntries(Object.keys(values).map(k=>[k,process.env[k]]));
 try{Object.assign(process.env,values);const actual=gitRead(['rev-parse','HEAD']);assert.equal(actual.status,0);assert.equal(actual.stdout,baseline.stdout);assert.equal(gitRead(['rev-parse','--show-toplevel']).stdout.trim(),repo);}
 finally{for(const [k,v]of Object.entries(original)){if(v===undefined)delete process.env[k];else process.env[k]=v;}}
}));
test('status-only guard permits exact common-certificate tuples, rejects credential/HA/redirect URLs',async()=>{
 const crl=new Request('http://crl.apple.com/applerootcag3.crl',{headers:{accept:'application/pkix-crl'}});assert.equal(allowedStatusRequest(crl),true);
 for(const suffix of ['ocsp03-applerootcag3','ocsp03-aaica5g101'])assert.equal(allowedStatusRequest(new Request('http://ocsp.apple.com/'+suffix,{method:'POST',headers:{accept:'application/ocsp-response','content-type':'application/ocsp-request'},body:new Uint8Array([1])})),true);
 for(const request of [new Request('https://ha.example/'),new Request(crl.url+'?extra=1',{headers:crl.headers}),new Request(crl.url,{headers:{...Object.fromEntries(crl.headers),authorization:'Bearer synthetic'}}),new Request('https://crl.apple.com/applerootcag3.crl',{headers:crl.headers})]){assert.equal(allowedStatusRequest(request),false);assert.equal((await statusOnlyOutbound(request)).status,503);}
});
test('host file adapter preserves exact action clientData bytes without interpreting signed JSON',async()=>privateTest(async dir=>{
 const clientData=Buffer.from('{"exact":"native action bytes"}'),nonce=Buffer.alloc(32,5);
 await writeFile(join(dir.path,'request.json'),encoded('/submit-challenge',{v:V}),{mode:0o600});
 // Pure host I/O fixture, not an enrolled key, fake verifier or workerd positive.
 const fixture={verifySources:async()=>{},snapshot:{head:'host-io-fixture',pins:{}},bundle_sha256:'host-io-fixture',request:async()=>Response.json({v:V,challenge:'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU',client_data:clientData.toString('base64url'),expires_at:Date.now()+120000})};
 assert.equal(await processRequest(dir,fixture,1),200);assert.deepEqual(await readFile(join(dir.path,'01-client-data.bin')),clientData);assert.deepEqual(await readFile(join(dir.path,'01-nonce.bin')),nonce);
 await assert.rejects(processRequest(dir,fixture,1));
}));
test('actual private workerd: default genuine rejection/original120s nonce/zero installed keys; file output exact; restart isolated', {timeout:180000},async()=>{
 let runtime=await startLocalRuntime();
 const key=Buffer.alloc(32,3).toString('base64');
 const body={v:V,key_id:key,action:'register'};
 const call=async(route,b)=>{const response=await runtime.request(route,Buffer.from(JSON.stringify(b)));return {status:response.status,body:await response.json()};};
 let first;
 try{
  await privateTest(async dir=>{
   await writeFile(join(dir.path,'request.json'),encoded('/attestation/challenge',body),{mode:0o600});
   assert.equal(await processRequest(dir,runtime,1),200);
   first=JSON.parse(await readFile(join(dir.path,'01-response.json')));
   assert.equal((await readFile(join(dir.path,'01-nonce.bin'))).toString('base64url'),first.challenge);
   const receipt=JSON.parse(await readFile(join(dir.path,'01-receipt.json')));assert.equal(receipt.status,200);assert.ok(!JSON.stringify(receipt).includes(first.challenge));assert.ok(!JSON.stringify(receipt).includes(key));
  });
  const original=await runtime.enrollmentObservation(key);assert.deepEqual(original.keys,[{n:0}]);assert.equal(original.operations.length,1);
  const operation=JSON.parse(original.operations[0].value);assert.equal(operation.expiresAt-operation.createdAt,120000);assert.equal(operation.nonce,first.challenge);assert.equal(operation.id,first.challenge_id);
  const rejected=await call('/attestation/register',{v:V,key_id:key,challenge_id:first.challenge_id,attestation:'AA'});assert.equal(rejected.status,401);assert.deepEqual(rejected.body,{v:V,error:'invalid_sender_proof'});
  const preserved=await runtime.enrollmentObservation(key);assert.deepEqual(preserved,original);
  assert.deepEqual((await call('/attestation/challenge',body)).body,first);
  const other=await call('/attestation/register',{v:V,key_id:Buffer.alloc(32,4).toString('base64'),challenge_id:first.challenge_id,attestation:'AA'});assert.equal(other.status,401);
  assert.deepEqual(runtime.egressObservation(),{allowed:0,denied:0});
  // Real wall-clock expiry: never advance the runtime clock or renew the operation.
  await new Promise(resolve=>setTimeout(resolve,Math.max(0,first.expires_at-Date.now()+50)));
  assert.equal((await call('/attestation/register',{v:V,key_id:key,challenge_id:first.challenge_id,attestation:'AA'})).status,401);
  assert.deepEqual((await runtime.enrollmentObservation(key)).keys,[{n:0}]);
 }finally{await runtime.stop();}
 runtime=await startLocalRuntime();try{const fresh=await call('/attestation/challenge',body);assert.equal(fresh.status,200);assert.notEqual(fresh.body.challenge_id,first.challenge_id);assert.notEqual(fresh.body.challenge,first.challenge);}finally{await runtime.stop();}
});
