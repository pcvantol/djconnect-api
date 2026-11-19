/** Offline candidate protocol: possession of a presented key is DATA, never enrollment. */
import {canonical,parseStrictJson,SurfaceError} from '../../src/surface-push/wire';

const DOMAIN='DJC-CORE-INSTALL-PRINCIPAL-POSSESSION-CANDIDATE-V1';
const AUDIENCE='djc-private-principal-registry/1';
const Q=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const FIELDS=['audience','challenge_id','challenge_nonce_sha256','core_installation_binding_sha256',
  'core_instance_id','expected_registry_revision','installation_id','operator_admission_binding_sha256',
  'original_authorization_deadline_unix_ms','policy_sha256','principal_epoch','principal_id',
  'public_key_jwk','public_key_pin_sha256','registration_operation_id','registry_identity_sha256',
  'registry_restore_policy_sha256','version'] as const;
const HASHES=['challenge_nonce_sha256','core_installation_binding_sha256','operator_admission_binding_sha256',
  'policy_sha256','public_key_pin_sha256','registry_identity_sha256','registry_restore_policy_sha256'] as const;
type InputCode='invalid_body'|'transcript_mismatch'|'invalid_signature_encoding'|
  'invalid_signature_scalar'|'public_key_pin_mismatch';
export class PossessionDataInputError extends Error {
  constructor(readonly code:InputCode,cause?:unknown) {super(code,{cause});this.name='PossessionDataInputError';}
}
function need(ok:unknown,code:InputCode='invalid_body'):asserts ok {
  if(!ok)throw new PossessionDataInputError(code);
}
function closed(v:unknown,fields:readonly string[]):asserts v is Record<string,unknown> {
  need(v!==null && typeof v==='object' && !Array.isArray(v));
  need(Object.keys(v).length===fields.length && fields.every(k=>Object.hasOwn(v,k)));
}
function base64(bytes:Uint8Array):string {
  return btoa(Array.from(bytes,b=>String.fromCharCode(b)).join('')).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
function bytes(v:unknown,length:number,code:InputCode):Uint8Array<ArrayBuffer> {
  need(typeof v==='string' && v.length===Math.ceil(length*8/6) && /^[A-Za-z0-9_-]+$/.test(v),code);
  let raw:string;
  try {raw=atob(v.replaceAll('-','+').replaceAll('_','/'));}
  catch(cause) {throw new PossessionDataInputError(code,cause);}
  const result=Uint8Array.from(raw,c=>c.charCodeAt(0));
  need(result.length===length && base64(result)===v,code);return result;
}
interface PublicPoint {crv:'P-256';kty:'EC';x:string;y:string}
interface Transcript {
  registration_operation_id:string;challenge_id:string;principal_id:string;principal_epoch:number;
  expected_registry_revision:number;original_authorization_deadline_unix_ms:number;
  public_key_jwk:PublicPoint;public_key_pin_sha256:string;
}
function body(text:unknown):{text:string;value:Transcript} {
  // Reject large strings before UTF8 allocation. All admitted string values are ASCII.
  need(typeof text==='string' && text.length>0 && text.length<=4096 && new TextEncoder().encode(text).length<=4096);
  let v:unknown;
  try {v=parseStrictJson(text);}
  catch(cause) {if(cause instanceof SurfaceError)throw new PossessionDataInputError('invalid_body',cause);throw cause;}
  closed(v,FIELDS);need(v.version===1 && v.audience===AUDIENCE);
  for(const key of ['registration_operation_id','challenge_id'])need(typeof v[key]==='string' &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v[key] as string));
  for(const key of ['core_instance_id','installation_id','principal_id'])need(typeof v[key]==='string' && /^[A-Za-z0-9._:-]{1,128}$/.test(v[key] as string));
  for(const key of HASHES)need(typeof v[key]==='string' && /^[a-f0-9]{64}$/.test(v[key] as string));
  for(const [key,min,max] of [['principal_epoch',1,Number.MAX_SAFE_INTEGER-1],['expected_registry_revision',0,Number.MAX_SAFE_INTEGER-1],
    ['original_authorization_deadline_unix_ms',1,Number.MAX_SAFE_INTEGER]] as const)
    need(Number.isSafeInteger(v[key]) && (v[key] as number)>=min && (v[key] as number)<=max);
  const jwk=v.public_key_jwk;closed(jwk,['crv','kty','x','y']);need(jwk.crv==='P-256' && jwk.kty==='EC');
  bytes(jwk.x,32,'invalid_body');bytes(jwk.y,32,'invalid_body');
  need(canonical(v)===text); // Reject aliases, whitespace, -0, exponents, BOM and trailing LF.
  Object.freeze(jwk);Object.freeze(v);
  return {text,value:v as unknown as Transcript};
}
function signature(v:unknown):Uint8Array<ArrayBuffer> {
  const b=bytes(v,64,'invalid_signature_encoding');
  const integer=(part:Uint8Array)=>part.reduce((n,x)=>(n<<8n)|BigInt(x),0n);
  const r=integer(b.subarray(0,32)),s=integer(b.subarray(32));
  need(r>0n && r<Q && s>0n && s<Q,'invalid_signature_scalar');return b;
}
async function digest(bytes:Uint8Array<ArrayBuffer>):Promise<string> {
  const hash=await crypto.subtle.digest('SHA-256',bytes);
  return Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('');
}
export interface PossessionData {
  readonly classification:'KEY_POSSESSION_DATA_ONLY';
  readonly registration_operation_id:string;readonly challenge_id:string;
  readonly principal_id:string;readonly principal_epoch:number;
  readonly expected_registry_revision:number;readonly original_authorization_deadline_unix_ms:number;
  readonly public_key_pin_sha256:string;readonly body_sha256:string;readonly signing_input_sha256:string;
}
/**
 * Expected is a separately supplied original DATA snapshot, not an authority port.
 * Invalid signature returns null; malformed DATA throws InputError. Crypto errors,
 * including public-point import failures, propagate unchanged. No clocks/once/admission.
 */
export async function verifyPossessionData(expectedBody:unknown,proofBody:unknown,signatureBase64url:unknown):Promise<Readonly<PossessionData>|null> {
  // Only primitive strings cross this boundary; parsing produces private owned snapshots.
  const expected=body(expectedBody),proof=body(proofBody);
  need(expected.text===proof.text,'transcript_mismatch');
  const sig=signature(signatureBase64url),encoder=new TextEncoder();
  const bodyBytes=Uint8Array.from(encoder.encode(expected.text)),signingBytes=Uint8Array.from(encoder.encode(DOMAIN+'\n'+expected.text));
  const pin=await digest(Uint8Array.from(encoder.encode(canonical(expected.value.public_key_jwk))));
  need(pin===expected.value.public_key_pin_sha256,'public_key_pin_mismatch');
  const key=await crypto.subtle.importKey('jwk',expected.value.public_key_jwk,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,sig,signingBytes))return null;
  const [bodyHash,inputHash]=await Promise.all([digest(bodyBytes),digest(signingBytes)]);
  const v=expected.value;
  return Object.freeze({classification:'KEY_POSSESSION_DATA_ONLY',registration_operation_id:v.registration_operation_id,
    challenge_id:v.challenge_id,principal_id:v.principal_id,principal_epoch:v.principal_epoch,
    expected_registry_revision:v.expected_registry_revision,original_authorization_deadline_unix_ms:v.original_authorization_deadline_unix_ms,
    public_key_pin_sha256:pin,body_sha256:bodyHash,signing_input_sha256:inputHash});
}
