// Host-only operator file bridge; never imported by the product Worker.
import {constants as F} from 'node:fs';
import {open,realpath,lstat} from 'node:fs/promises';
import {resolve,join} from 'node:path';

export const ROUTES=Object.freeze(['/create','/poll','/consume','/cancel','/inspect','/attestation/challenge','/attestation/register','/submit-challenge','/submit','/attestation/delete','/attestation/recover']);
export const need=value=>{if(!value)throw new Error('local_experiment_rejected');};
const owned=(s,mode)=>s.uid===process.getuid()&&(s.mode&0o777)===mode;
export async function privateDirectory(path,repo){
 const dir=resolve(path),canonical=await realpath(dir),root=await realpath(repo);
 need(dir===canonical&&dir!==root&&!dir.startsWith(root+'/'));
 const s=await lstat(dir);need(s.isDirectory()&&!s.isSymbolicLink()&&owned(s,0o700));
 return {path:dir,dev:s.dev,ino:s.ino};
}
export async function checkDirectory(dir){
 const s=await lstat(dir.path);
 need(s.isDirectory()&&!s.isSymbolicLink()&&owned(s,0o700)&&s.dev===dir.dev&&s.ino===dir.ino&&await realpath(dir.path)===dir.path);
}
const leaf=name=>need(/^[a-z0-9][a-z0-9.-]{0,90}$/.test(name));
export async function readPrivate(dir,name,max=102400){
 leaf(name);await checkDirectory(dir);
 const f=await open(join(dir.path,name),F.O_RDONLY|F.O_NOFOLLOW|F.O_NONBLOCK);
 try{
  const s=await f.stat();need(s.isFile()&&s.nlink===1&&owned(s,0o600)&&s.size>0&&s.size<=max);
  const bytes=Buffer.alloc(s.size+1);const {bytesRead}=await f.read(bytes,0,bytes.length,0);
  const after=await f.stat();need(bytesRead===s.size&&after.size===s.size&&after.mtimeMs===s.mtimeMs&&after.ctimeMs===s.ctimeMs);
  await checkDirectory(dir);return bytes.subarray(0,bytesRead);
 }finally{await f.close();}
}
export async function writePrivate(dir,name,bytes){
 leaf(name);await checkDirectory(dir);
 const f=await open(join(dir.path,name),F.O_WRONLY|F.O_CREAT|F.O_EXCL|F.O_NOFOLLOW,0o600);
 try{
  const s=await f.stat();need(s.isFile()&&s.nlink===1&&owned(s,0o600));
  await f.writeFile(bytes);await f.sync();await checkDirectory(dir);
 }finally{await f.close();}
}
export function decode64(value,max=102400){
 need(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(max*4/3)&&/^[A-Za-z0-9_-]+$/.test(value));
 const bytes=Buffer.from(value,'base64url');need(bytes.length>0&&bytes.length<=max&&bytes.toString('base64url')===value);return bytes;
}
export function parseRequest(bytes){
 // The tiny envelope is canonical JSON, eliminating duplicate-key ambiguity.
 // Its body remains opaque bytes; product ingress owns JSON/schema validation.
 const s=new TextDecoder('utf-8',{fatal:true}).decode(bytes),v=JSON.parse(s);
 need(v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).length===2&&ROUTES.includes(v.route)&&typeof v.body_base64url==='string');
 need(s===JSON.stringify({route:v.route,body_base64url:v.body_base64url}));
 return {route:v.route,body:decode64(v.body_base64url,73728)};
}
export class CommandBudget{
 #started=Date.now();#count=0;
 take(){const now=Date.now();need(now>=this.#started&&now-this.#started<900000&&this.#count<16);return ++this.#count;}
}
