// Fixed host-only preparation. This descriptor is NOT operator/device admission.
import {createHash} from 'node:crypto';
import {mkdir,writeFile,readFile,lstat,readdir} from 'node:fs/promises';
import {join,dirname,resolve} from 'node:path';
import {need} from './local-native-files.mjs';

const hash=b=>createHash('sha256').update(b).digest('hex');
export const CORE='qualification/rendezvous/app-attest-core-candidate.mjs';
const ORIGINAL="const BUILDS = new Set(['40227', '40228', '40230']);";
const DERIVED="const BUILDS = new Set(['40381']);";
export const PROFILE=Object.freeze({
 id:'private-40381-registration-recover/1',scope:'PREPARED_ONLY_NOT_NATIVE_ADMITTED',build:'40381',
 apple_source:'0db4e137964a94ca2798b0efd89f6268db2b3261',
 proposal_sha256:'53ce83e05aede3f7a2e2c66890e2ce9be213aa8a4e023f0743c8c3637e91ad2c',
 artifact_manifest_sha256:'166dceca1a2217d69e7510be3182dc64075ff770113d94294e9e867637b51c2a',
 team:'ZEML4LPXH4',app:'dev.djconnect.ios',environment:'development',
 profile_sha256:'9243e1b2b3c829a86073ecf61f50e13cb7f0c9ab0630c9597ca3e9fa286629dd',
 native_run_admitted:false,
});
export function derive40381(bytes){
 const s=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
 need(s.split(ORIGINAL).length===2&&!s.includes(DERIVED));
 return Buffer.from(s.replace(ORIGINAL,DERIVED));
}
async function walk(root,prefix='',out=[]){
 const dir=join(root,prefix),s=await lstat(dir);
 need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o777)===0o700);
 for(const name of await readdir(dir)){
  const rel=prefix?prefix+'/'+name:name,f=await lstat(join(root,rel));
  if(f.isDirectory())await walk(root,rel,out);
  else {need(f.isFile()&&!f.isSymbolicLink()&&f.nlink===1&&f.uid===process.getuid()&&(f.mode&0o777)===0o600);out.push(rel);}
 }
 return out;
}
export async function stage40381(snapshot,repo,parent){
 const root=join(parent,'profile-source');await mkdir(root,{mode:0o700});
 const pins={};
 for(const [name,expected] of Object.entries(snapshot.pins)){
  if(name.startsWith('node_modules/'))continue; //32 original pinned package files stay outside this copy.
  need(!name.startsWith('/')&&!name.split('/').some(p=>p==='..'||p==='.'||p===''));
  const b=await readFile(join(repo,name));need(hash(b)===expected);
  const content=name===CORE?derive40381(b):b;
  await mkdir(dirname(join(root,name)),{recursive:true,mode:0o700});
  await writeFile(join(root,name),content,{mode:0o600,flag:'wx'});pins[name]=hash(content);
 }
 const verify=async()=>{
  const actual=(await walk(root)).sort(),expected=Object.keys(pins).sort();need(JSON.stringify(actual)===JSON.stringify(expected));
  for(const name of expected){
   const b=await readFile(join(root,name));need(hash(b)===pins[name]);
   if(name!==CORE)need(pins[name]===snapshot.pins[name]);
   else {const original=await readFile(join(repo,name));need(hash(original)===snapshot.pins[name]&&hash(derive40381(original))===pins[name]);}
  }
 };
 await verify();
 return {root,pins,verify,receipt:{...PROFILE,source_core_sha256:snapshot.pins[CORE],derived_core_sha256:pins[CORE],copied_files:Object.keys(pins).length}};
}
export function check40381Graph(metadata,stage,snapshot,repo,scratch){
 const inputs=Object.keys(metadata.inputs).filter(p=>!p.startsWith('node-built-in-modules:')).map(p=>resolve(scratch,p));
 const wanted=[CORE,'qualification/rendezvous/enrollment-evidence-candidate.mjs','qualification/rendezvous/assertion-key-state.ts'];
 for(const name of wanted)need(inputs.filter(p=>p===join(stage.root,name)).length===1);
 for(const input of inputs){
  if(input===join(scratch,'driver.ts'))continue;
  if(input.startsWith(stage.root+'/'))need(Object.hasOwn(stage.pins,input.slice(stage.root.length+1)));
  else need(input.startsWith(repo+'/node_modules/')&&Object.hasOwn(snapshot.pins,input.slice(repo.length+1)));
 }
 need(!inputs.includes(join(repo,CORE)));
}

// Four commands total; same key throughout, original server challenge IDs/bytes.
// No retry, new-key loop, submit, delete or transaction route is admitted here.
export function registrationRecoverController(send){
 let step=0,busy=false,key,challenge,clientData;
 return async(route,body)=>{
  need(!busy&&step<4);busy=true;const current=step;step=4; //Any failed/uncertain attempt is terminal.
  try{
   need(body instanceof Uint8Array&&body.length<=73728);
   const v=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(body));
   need(v&&v.v==='djc-rendezvous/1'&&typeof v.key_id==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(v.key_id));
   need(Buffer.from(v.key_id,'base64').toString('base64')===v.key_id);
   if(current===0){need(route==='/attestation/challenge'&&v.action==='register');key=v.key_id;}
   else need(v.key_id===key);
   if(current===1)need(route==='/attestation/register'&&v.challenge_id===challenge);
   if(current===2)need(route==='/attestation/challenge'&&v.action==='recover-key');
   if(current===3)need(route==='/attestation/recover'&&v.challenge_id===challenge&&v.client_data===clientData);
   const response=await send(route,body);
   const result=await response.clone().json();
   if(response.ok){
    if(current===0||current===2){
     need(result.v==='djc-rendezvous/1'&&typeof result.challenge_id==='string'&&/^[A-Za-z0-9_-]{43}$/.test(result.challenge_id));challenge=result.challenge_id;
     if(current===2){need(typeof result.client_data==='string');clientData=result.client_data;}
    }
    step=current+1;
   }
   return response;
  }finally{busy=false;}
 };
}
