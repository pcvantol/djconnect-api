// Software-only interoperability tool. Never import into the product Worker.
import {readFile,readdir,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve,join,sep} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';

const MAX_INPUT=16384,MAX_PLAINTEXT=2048,MAX_ENVELOPE=8192;
const need=value=>{if(!value)throw new Error('vector_generation_rejected');};
const hash=value=>createHash('sha256').update(value).digest('hex');
const keys=(value,names)=>{need(value!==null&&typeof value==='object'&&!Array.isArray(value));need(Object.keys(value).sort().join(',')===[...names].sort().join(','));};
const base64url=(value,length)=>{
 need(typeof value==='string'&&/^[A-Za-z0-9_-]+$/.test(value));
 const decoded=Buffer.from(value,'base64url');need(decoded.length===length&&decoded.toString('base64url')===value);return decoded;
};
export function parseVectorInput(raw){
 need(raw instanceof Uint8Array&&raw.length>0&&raw.length<=MAX_INPUT);
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),input=JSON.parse(text),canonical=JSON.stringify(input);
 // CLI framing only: compact JSON.stringify form, optionally one final LF.
 // Roundtrip equality rejects duplicate keys/alternate numeric spelling without a new JSON parser.
 need(text===canonical||text===canonical+'\n');
 keys(input,['jwk','thumbprint','plaintext']);keys(input.jwk,['kty','n','e']);
 need(input.jwk.kty==='RSA'&&input.jwk.e==='AQAB');
 const modulus=base64url(input.jwk.n,256);need((modulus[0]&128)!==0&&(modulus[255]&1)===1);
 base64url(input.thumbprint,32);
 const p=input.plaintext;
 keys(p,['v','transaction_id','generation','browser_key_thumbprint','expires_at','bootstrap_origin','display_entry_url','issuer_epoch']);
 need(p.v==='djc-rendezvous/1'&&p.bootstrap_origin==='https://vibecast.tv');
 need(typeof p.transaction_id==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(p.transaction_id));
 need(Number.isInteger(p.generation)&&p.generation>=1&&p.generation<=2147483647);
 need(Number.isSafeInteger(p.expires_at)&&p.expires_at>=0);
 need(p.browser_key_thumbprint===input.thumbprint);base64url(p.issuer_epoch,32);
 // Reserved example DNS only. This tool is not a production HA destination validator.
 need(typeof p.display_entry_url==='string'&&p.display_entry_url.length<=512);
 const match=/^https:\/\/([a-z0-9.-]+)\/djconnect\/vibecast\/display$/.exec(p.display_entry_url);need(match);
 const host=match[1];need(host.length<=253&&host.split('.').every(label=>label.length>=1&&label.length<=63&&/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)&&!label.startsWith('xn--')));
 need(host==='example.org'||host.endsWith('.example.org')||host==='example.com'||host.endsWith('.example.com')||host==='example.net'||host.endsWith('.example.net')||host.endsWith('.example'));
 need(Buffer.byteLength(JSON.stringify(p),'utf8')<=MAX_PLAINTEXT);return input;
}
export async function loadPinnedJose(packageDirectory){
 const root=await realpath(resolve(packageDirectory)),repo=await realpath(fileURLToPath(new URL('../../',import.meta.url)));
 need(root!==repo&&!root.startsWith(repo+sep));
 const manifest=JSON.parse(await readFile(new URL('./jwe-dependency-provenance-v1.json',import.meta.url),'utf8'));
 need(manifest.package==='jose'&&manifest.version==='6.2.12');
 const actual=[];
 async function walk(directory,prefix=''){
  for(const entry of await readdir(directory,{withFileTypes:true})){
   need(!entry.isSymbolicLink());const relative=prefix+entry.name,path=join(directory,entry.name);
   if(entry.isDirectory())await walk(path,relative+'/');else{need(entry.isFile());actual.push(relative);}
  }
 }
 await walk(root);need(JSON.stringify(actual.sort())===JSON.stringify(Object.keys(manifest.files_sha256).sort()));
 for(const name of actual)need(hash(await readFile(join(root,name)))===manifest.files_sha256[name]);
 const pkg=JSON.parse(await readFile(join(root,'package.json'),'utf8'));need(pkg.name==='jose'&&pkg.version==='6.2.12'&&!pkg.dependencies);
 return import(pathToFileURL(join(root,'dist/webapi/index.js')).href);
}
export async function encryptVector(input,jose){
 need(await jose.calculateJwkThumbprint(input.jwk,'sha256')===input.thumbprint);
 const key=await jose.importJWK(input.jwk,'RSA-OAEP-256');
 const token=await new jose.CompactEncrypt(new TextEncoder().encode(JSON.stringify(input.plaintext)))
  .setProtectedHeader({alg:'RSA-OAEP-256',enc:'A256GCM',typ:'djc-rendezvous-destination+jwe',kid:input.thumbprint}).encrypt(key);
 need(token.length<=MAX_ENVELOPE);return token;
}
async function main(){
 need(process.argv.length===3);const chunks=[];let size=0;
 for await(const chunk of process.stdin){size+=chunk.length;need(size<=MAX_INPUT);chunks.push(chunk);}
 const input=parseVectorInput(Buffer.concat(chunks));
 const jose=await loadPinnedJose(process.argv[2]),envelope=await encryptVector(input,jose);
 process.stdout.write(envelope+'\n'); // The only success output; no plaintext, key, metadata or diagnostics.
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main().catch(()=>{process.stderr.write('vector_generation_rejected\n');process.exitCode=1;});
}
