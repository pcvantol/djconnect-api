// Explicit operator commands only. Keep private proof data out of argv/stdout.
import {createInterface} from 'node:readline';
import {pathToFileURL} from 'node:url';
import {privateDirectory,readPrivate,writePrivate,parseRequest,decode64,CommandBudget,need} from './local-native-files.mjs';
import {startLocalRuntime,repo} from './local-native-runtime.mjs';

export async function processRequest(dir,runtime,sequence){
 await runtime.verifySources();
 const request=parseRequest(await readPrivate(dir,'request.json'));
 const started=Date.now(),response=await runtime.request(request.route,request.body),body=new Uint8Array(await response.arrayBuffer());
 need(body.length<=102400);
 const prefix=String(sequence).padStart(2,'0');
 await writePrivate(dir,prefix+'-response.json',body);
 if(response.ok&&['/attestation/challenge','/submit-challenge'].includes(request.route)){
  const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));
  need(Number.isSafeInteger(result.expires_at)&&result.expires_at>started&&result.expires_at<=Date.now()+120000);
  const nonce=decode64(result.challenge,32);need(nonce.length===32);
  await writePrivate(dir,prefix+'-nonce.bin',nonce);
  if(result.client_data)await writePrivate(dir,prefix+'-client-data.bin',decode64(result.client_data,8192));
 }
 // Fixed, sanitized receipt only; no raw wire, proof, key handle or destination.
 await writePrivate(dir,prefix+'-receipt.json',JSON.stringify({scope:'PREPARED_LOCAL_EXPERIMENT_NOT_REACHABLE_NATIVE_TARGET',source:runtime.snapshot.head,source_hashes:runtime.snapshot.pins,bundle_sha256:runtime.bundle_sha256,route:request.route,status:response.status,started_at:started,finished_at:Date.now()}));
 return response.status;
}
async function main(){
 need(process.argv.length===3);process.umask(0o077);
 const dir=await privateDirectory(process.argv[2],repo),budget=new CommandBudget();
 // Reserve the directory once per experiment; a restart cannot resume old state.
 await writePrivate(dir,'experiment-started.json',JSON.stringify({scope:'PREPARED_LOCAL_EXPERIMENT_NOT_REACHABLE_NATIVE_TARGET',started_at:Date.now()}));
 let runtime;
 const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
 const finish=async()=>{lines.close();if(runtime){const current=runtime;runtime=undefined;await current.stop();}};
 const signal=()=>{void finish().finally(()=>process.exit(1));};process.once('SIGTERM',signal);process.once('SIGINT',signal);
 try{
  runtime=await startLocalRuntime();console.log('PREPARED_LOCAL_EXPERIMENT_NOT_REACHABLE_NATIVE_TARGET; process | stop');
  for await(const line of lines){
   if(line==='stop')break;
   need(line==='process');const sequence=budget.take();
   const status=await processRequest(dir,runtime,sequence);console.log(JSON.stringify({sequence,status}));
  }
 }finally{await finish();process.removeListener('SIGTERM',signal);process.removeListener('SIGINT',signal);}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{console.error('LOCAL_EXPERIMENT_STOPPED; private files retained; no automatic retry');process.exitCode=1;});
