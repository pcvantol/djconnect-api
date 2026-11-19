import {it,expect,beforeEach,afterEach,vi} from 'vitest';
import {SELF} from 'cloudflare:test';
import {canonical} from '../../../src/surface-push/wire';
import {verifyPossessionData,PossessionDataInputError} from '../possession-data';
import vector from '../public-vectors.json';

const run=(expected:unknown=vector.body,proof:unknown=vector.body,sig:unknown=vector.signature_b64url)=>verifyPossessionData(expected,proof,sig);
const changed=(key:string,value:unknown)=>canonical({...JSON.parse(vector.body),[key]:value});
const H=(n:number)=>n.toString(16).padStart(64,'0');
const b64=(b:Uint8Array)=>btoa(Array.from(b,x=>String.fromCharCode(x)).join('')).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
let egress:ReturnType<typeof vi.fn>;
beforeEach(()=>{
  egress=vi.fn(()=>{throw Error('egress forbidden');});vi.stubGlobal('fetch',egress);
  vi.spyOn(crypto.subtle,'generateKey').mockImplementation(()=>{throw Error('key generation forbidden');});
  vi.spyOn(crypto.subtle,'sign').mockImplementation(()=>{throw Error('private signing forbidden');});
  vi.spyOn(crypto,'getRandomValues').mockImplementation(()=>{throw Error('randomness forbidden');});
});
afterEach(()=>{
  expect(egress).not.toHaveBeenCalled();expect(crypto.subtle.generateKey).not.toHaveBeenCalled();
  expect(crypto.subtle.sign).not.toHaveBeenCalled();expect(crypto.getRandomValues).not.toHaveBeenCalled();
  vi.restoreAllMocks();vi.unstubAllGlobals();
});
it('real workerd verifies exact expired public software fixture as frozen DATA, never permission',async()=>{
  const result=await run();expect(result).toEqual({classification:'KEY_POSSESSION_DATA_ONLY',
    registration_operation_id:'00000000-0000-4000-8000-000000000001',challenge_id:'00000000-0000-4000-8000-000000000002',
    principal_id:'fixture-principal-not-enrolled',principal_epoch:1,expected_registry_revision:0,
    original_authorization_deadline_unix_ms:1700000000000,public_key_pin_sha256:vector.public_jwk_pin_sha256,
    body_sha256:vector.body_sha256,signing_input_sha256:vector.signing_input_sha256});
  expect(Object.isFrozen(result)).toBe(true);expect(Reflect.set(result!,'principal_epoch',2)).toBe(false);
  expect(result).not.toHaveProperty('admitted');expect(result).not.toHaveProperty('is_current');
});
it('both genuine S aliases and repeated crypto verification have identical original DATA identity',async()=>{
  const first=await run(),other=await run(vector.body,vector.body,vector.opposite_s_signature_b64url);
  expect(first).not.toBeNull();expect(other).toEqual(first);expect(await run()).toEqual(first);
  expect(first).not.toHaveProperty('signature_sha256'); // no operation/nonce ledger or renewal exists here
});
it.each(vector.wrong_domain_signatures)('real proof from wrong domain $name is not accepted',async row=>{
  expect(await run(vector.body,vector.body,row.signature_b64url)).toBeNull();
});
it('original RFC signature is not a proof over this candidate transcript',async()=>{
  const old='DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
  expect(await run(vector.r1_encoding_body,vector.r1_encoding_body,old)).toBeNull();
});
it('valid signature cannot substitute the original expected body; reject before any crypto',async()=>{
  const imports=vi.spyOn(crypto.subtle,'importKey'),verify=vi.spyOn(crypto.subtle,'verify'),hash=vi.spyOn(crypto.subtle,'digest');
  await expect(run(vector.r1_encoding_body,vector.body)).rejects.toMatchObject({code:'transcript_mismatch'});
  expect(imports).not.toHaveBeenCalled();expect(verify).not.toHaveBeenCalled();expect(hash).not.toHaveBeenCalled();
});
it.each(vector.r1_negative_body_cases)('original R1 negative bytes reject: $name',async row=>{
  const bytes=Uint8Array.from(atob(row.body_b64url.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
  const proof=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
  await expect(run(vector.r1_encoding_body,proof)).rejects.toBeInstanceOf(PossessionDataInputError);
});
it.each([
  ['version',2],['audience','other'],['principal_epoch',0],['principal_epoch',Number.MAX_SAFE_INTEGER],
  ['expected_registry_revision',-1],['expected_registry_revision',Number.MAX_SAFE_INTEGER],
  ['original_authorization_deadline_unix_ms',0],['original_authorization_deadline_unix_ms',Number.MAX_SAFE_INTEGER+1],
  ['principal_epoch',1.5],['installation_id','é'],['principal_id','x'.repeat(129)],['core_instance_id',''],
  ['registration_operation_id','00000000-0000-7000-8000-000000000001'],['challenge_id','00000000-0000-4000-C000-000000000002'],
  ['policy_sha256','F'.repeat(64)],['registry_identity_sha256',null],['registry_restore_policy_sha256',H(1).slice(1)],
] as const)('invalid expected body %s rejects even when proof matches',async(key,value)=>{
  const text=changed(key,value);await expect(run(text,text)).rejects.toMatchObject({code:'invalid_body'});
});
it('missing original expected, null/array/oversized/non-string bodies reject without coercion',async()=>{
  const toString=vi.fn(()=>vector.body),obj={toString};
  for(const value of [undefined,null,[],{},obj,vector.body+' '.repeat(4096)])
    await expect(verifyPossessionData(value,vector.body,vector.signature_b64url)).rejects.toBeInstanceOf(PossessionDataInputError);
  expect(toString).not.toHaveBeenCalled();
});
it('escaped duplicate field, unknown member and nested JWK key-order aliases reject',async()=>{
  const duplicate=vector.body.slice(0,-1)+',"\\u0076ersion":1}';
  const jwk=JSON.parse(vector.body).public_key_jwk;
  const reordered=vector.body.replace(canonical(jwk),JSON.stringify({kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y}));
  for(const wire of [duplicate,reordered,changed('allow_admission',true)])await expect(run(wire,wire)).rejects.toMatchObject({code:'invalid_body'});
});
it('public pin is recomputed, never treated as proof or authority',async()=>{
  const wrong=changed('public_key_pin_sha256',H(8)),imports=vi.spyOn(crypto.subtle,'importKey');
  await expect(run(wrong,wrong)).rejects.toMatchObject({code:'public_key_pin_mismatch'});expect(imports).not.toHaveBeenCalled();
});
it.each(['d','alg','kid','use','key_ops'])('extra JWK %s is rejected',async key=>{
  const jwk=JSON.parse(vector.body).public_key_jwk,text=changed('public_key_jwk',{...jwk,[key]:'not-a-key'});
  await expect(run(text,text)).rejects.toMatchObject({code:'invalid_body'});
});
it('actual public-key import rejects an off-curve point without returning DATA',async()=>{
  const jwk={crv:'P-256',kty:'EC',x:'A'.repeat(43),y:'A'.repeat(43)};
  const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(canonical(jwk)));
  const text=canonical({...JSON.parse(vector.body),public_key_jwk:jwk,
    public_key_pin_sha256:Array.from(new Uint8Array(hash),x=>x.toString(16).padStart(2,'0')).join('')});
  await expect(run(text,text)).rejects.toThrow();
});
it.each(vector.r1_scalar_cases)('R1 scalar boundary $name',async row=>{
  if(row.expected_precrypto==='REJECT_RANGE')await expect(run(vector.body,vector.body,row.signature_b64url)).rejects.toMatchObject({code:'invalid_signature_scalar'});
  else expect(await run(vector.body,vector.body,row.signature_b64url)).toBeNull(); // in-range is not a valid signature
});
it('padded, oversized, wrong-length, noncanonical base64 and DER encodings reject',async()=>{
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',s=vector.signature_b64url;
  const alias=s.slice(0,-1)+alphabet[alphabet.indexOf(s.at(-1)!)+1];
  for(const wire of [s+'==',s.slice(1),s+'A','A'.repeat(10000),s.replace(/./,'+'),alias,'MEQCIA'+'A'.repeat(90),null])
    await expect(run(vector.body,vector.body,wire)).rejects.toMatchObject({code:'invalid_signature_encoding'});
});
it('same valid schema with altered original body fails actual signature verification',async()=>{
  const wire=changed('challenge_nonce_sha256',H(40));expect(await run(wire,wire)).toBeNull();
});
it('bit-flipped but in-range signature returns null',async()=>{
  const raw=Uint8Array.from(atob(vector.signature_b64url.replaceAll('-','+').replaceAll('_','/')),x=>x.charCodeAt(0));raw[10]^=1;
  expect(await run(vector.body,vector.body,b64(raw))).toBeNull();
});
it.each(['digest','importKey','verify'] as const)('unexpected crypto %s failure preserves identical original cause',async method=>{
  const failure=new Error('unexpected crypto failure');vi.spyOn(crypto.subtle,method).mockRejectedValueOnce(failure);
  await expect(run()).rejects.toBe(failure);
});
it('post-verification output digest failure cannot return positive DATA',async()=>{
  const original=crypto.subtle.digest.bind(crypto.subtle),failure=new Error('output digest failure');let calls=0;
  vi.spyOn(crypto.subtle,'digest').mockImplementation((algorithm,data)=>++calls===1?original(algorithm,data):Promise.reject(failure));
  await expect(run()).rejects.toBe(failure);
});
it('the existing qualification HTTP worker remains closed; no new route is exported',async()=>{
  const response=await SELF.fetch('https://source.invalid/principal-possession',{method:'POST',body:vector.body});
  expect(response.status).toBe(503);expect(response.headers.get('Cache-Control')).toBe('no-store');
});
