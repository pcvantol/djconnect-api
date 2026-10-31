/** Closed private DATA only: no registry, signer, authority port or production caller. */
import {canonical,parseStrictJson,SurfaceError} from '../../src/surface-push/wire';
import schemaData from './schema-data.json';
const RECORD_DOMAIN='DJC-PRIVATE-INSTALLATION-RECORD-CANDIDATE-V1\n';
const POSSESSION_DOMAIN='DJC-CORE-INSTALL-PRINCIPAL-POSSESSION-CANDIDATE-V1\n';
const CLASSIFICATION='INSTALLATION_PRINCIPAL_DATA_ONLY' as const;
type Schema=Readonly<Record<string,string>>;
const schemas:Readonly<Record<string,Schema>>=schemaData.records;
const outcomes:Readonly<Record<string,Schema>>=schemaData.outcomes;
export type RecordType=keyof typeof schemaData.records;
export class InstallationDataError extends Error {
  constructor(readonly code:'invalid_data'|'original_mismatch'='invalid_data',cause?:unknown){super('installation_principal_data_invalid',{cause});}
}
function need(ok:unknown,code:'invalid_data'|'original_mismatch'='invalid_data'):asserts ok {if(!ok)throw new InstallationDataError(code);}
/** Lexical resource gate precedes even the strict parser, including embedded R1. */
function scan(input:unknown,bytes=32768,tokensMax=256):asserts input is string {
  need(typeof input==='string'&&input.length<=bytes&&/^[\x00-\x7f]*$/.test(input));
  // All admitted text is ASCII, so length is exactly its UTF8 byte count.
  const stack:string[]=[];let at=0,tokens=0;
  while(at<input.length){const c=input[at];
    if(/[\x20\x09\x0a\x0d,:]/.test(c)){at++;continue;}
    if(c==='{'||c==='['){need(stack.length<4);stack.push(c);tokens++;at++;}
    else if(c==='}'||c===']'){need(stack.pop()===(c==='}'?'{':'['));at++;}
    else if(c==='"'){
      tokens++;at++;let ended=false;
      while(at<input.length){const ch=input[at++];need(ch.charCodeAt(0)>=32);
        if(ch==='"'){ended=true;break;}
        if(ch==='\\'){need(at<input.length);const escaped=input[at++];
          if(escaped==='u'){need(/^[0-9a-fA-F]{4}$/.test(input.slice(at,at+4)));at+=4;}
          else need('"\\/bfnrt'.includes(escaped));}
      }need(ended);
    }else{const m=/^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(input.slice(at));need(m);at+=m[0].length;tokens++;}
    need(tokens<=tokensMax);
  }need(stack.length===0);
}
function object(v:unknown):asserts v is Record<string,unknown>{need(v!==null&&typeof v==='object'&&!Array.isArray(v));}
function closed(v:unknown,s:Schema):asserts v is Record<string,unknown>{object(v);need(Object.keys(v).length===Object.keys(s).length&&Object.keys(s).every(k=>Object.hasOwn(v,k)));}
function parsed(text:unknown,bytes=32768,tokens=256):Record<string,unknown>{
  scan(text,bytes,tokens);let v:unknown;
  try{v=parseStrictJson(text);}catch(cause){if(cause instanceof SurfaceError)throw new InstallationDataError('invalid_data',cause);throw cause;}
  object(v);need(canonical(v)===text);return v;
}
function freeze(v:Record<string,unknown>):Readonly<Record<string,unknown>>{
  for(const x of Object.values(v))if(x!==null&&typeof x==='object'){object(x);freeze(x);}return Object.freeze(v);
}
function point(v:unknown){closed(v,{crv:'',kty:'',x:'',y:''});need(v.crv==='P-256'&&v.kty==='EC');
  for(const k of ['x','y']){const s=v[k];need(typeof s==='string'&&/^[A-Za-z0-9_-]{43}$/.test(s));
    let raw:string;try{raw=atob(s.replaceAll('-','+').replaceAll('_','/'));}catch(cause){throw new InstallationDataError('invalid_data',cause);}
    need(raw.length===32&&btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')===s);}
  // Point import/on-curve/signature validity belongs to the independent crypto owner.
}
function typed(v:unknown,type:string):void{
  if(type==='literal1'||type==='literal2')need(v===Number(type.at(-1)));
  else if(type.startsWith('literal '))need(v===type.slice(8));
  else if(type.startsWith('enum '))need(typeof v==='string'&&type.slice(5).split('|').includes(v));
  else if(['counter','positive_counter','utc_ms'].includes(type))need(Number.isSafeInteger(v)&&(v as number)>=(type==='counter'?0:1)&&(v as number)<=(type==='utc_ms'?Number.MAX_SAFE_INTEGER:Number.MAX_SAFE_INTEGER-1));
  else if(['uuid4','sha256','opaque'].includes(type)){
    const pattern={uuid4:/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,sha256:/^[a-f0-9]{64}$/,opaque:/^[A-Za-z0-9._:-]{1,128}$/}[type as 'uuid4'|'sha256'|'opaque'];need(typeof v==='string'&&pattern.test(v));
  }else if(type==='public_P256_point')point(v);
  else if(type==='exact_R1_canonical_body_string'){const body=parsed(v,4096,128);validate(body,schemaData.R1);}
  else if(type==='closed_variant'){object(v);need(typeof v.tag==='string'&&Object.hasOwn(outcomes,v.tag));validate(v,outcomes[v.tag]);}
  else throw new InstallationDataError();
}
function validate(v:unknown,s:Schema):asserts v is Record<string,unknown>{closed(v,s);for(const [k,type]of Object.entries(s))typed(v[k],type);}
async function digest(text:string):Promise<string>{const b=Uint8Array.from(new TextEncoder().encode(text));const h=await crypto.subtle.digest('SHA-256',b);return Array.from(new Uint8Array(h),x=>x.toString(16).padStart(2,'0')).join('');}
async function pin(v:Record<string,unknown>){if(Object.hasOwn(v,'public_key_jwk'))need(await digest(canonical(v.public_key_jwk))===v.public_key_pin_sha256);}
export interface RecordData {readonly classification:typeof CLASSIFICATION;readonly record_type:RecordType;readonly canonical_text:string;readonly digest:string;readonly values:Readonly<Record<string,unknown>>}
export interface TranscriptData {readonly classification:typeof CLASSIFICATION;readonly canonical_text:string;readonly body_sha256:string;readonly signing_input_sha256:string;readonly values:Readonly<Record<string,unknown>>}
export async function decodeRecord(text:unknown,recordType:RecordType):Promise<Readonly<RecordData>>{
  need(typeof recordType==='string'&&Object.hasOwn(schemas,recordType));const v=parsed(text);validate(v,schemas[recordType]);
  const owned=freeze(v),original=text as string;await pin(v);
  // Embedded R1 is separately bounded and its original public pin checked, never signed.
  if(Object.hasOwn(v,'expected_transcript'))await decodeTranscript(v.expected_transcript);
  return Object.freeze({classification:CLASSIFICATION,record_type:recordType,canonical_text:original,digest:await digest(RECORD_DOMAIN+original),values:owned});
}
export async function decodeTranscript(text:unknown):Promise<Readonly<TranscriptData>>{
  const v=parsed(text,4096,128);validate(v,schemaData.R1);const owned=freeze(v),original=text as string;await pin(v);
  return Object.freeze({classification:CLASSIFICATION,canonical_text:original,body_sha256:await digest(original),signing_input_sha256:await digest(POSSESSION_DOMAIN+original),values:owned});
}
const CHAIN=['generation','receipt','subject','context','proof','original_expected_transcript'] as const;
/** Reject getters and retain only privately owned primitive copies before the first await. */
function snapshot(input:unknown,fields:readonly string[]):Readonly<Record<string,string>>{
  object(input);need(Object.getPrototypeOf(input)===Object.prototype||Object.getPrototypeOf(input)===null);
  const descriptors=Object.getOwnPropertyDescriptors(input);need(Reflect.ownKeys(descriptors).length===fields.length);
  const owned:Record<string,string>=Object.create(null);
  for(const k of fields){const d=descriptors[k];need(d&&Object.hasOwn(d,'value')&&typeof d.value==='string');owned[k]=d.value;}
  return Object.freeze(owned);
}
function same(a:Readonly<Record<string,unknown>>,b:Readonly<Record<string,unknown>>,fields:readonly string[]){for(const k of fields)need(canonical(a[k])===canonical(b[k]),'original_mismatch');}
function equal(a:unknown,b:unknown){need(a===b,'original_mismatch');}
async function chain(v:Readonly<Record<string,string>>){
  const g=await decodeRecord(v.generation,'custody_generation_preparation'),r=await decodeRecord(v.receipt,'custody_public_receipt'),s=await decodeRecord(v.subject,'installation_principal_subject'),c=await decodeRecord(v.context,'bootstrap_admission_context'),p=await decodeRecord(v.proof,'bootstrap_proof_preparation'),t=await decodeTranscript(v.original_expected_transcript);
  const [gv,rv,sv,cv,pv,tv]=[g,r,s,c,p,t].map(x=>x.values);
  equal(rv.generation_preparation_sha256,g.digest);same(rv,gv,['custody_operation_id','core_instance_id','installation_id','custody_epoch','custody_policy_sha256']);
  equal(sv.custody_public_receipt_sha256,r.digest);same(sv,rv,['custody_operation_id','core_instance_id','installation_id','custody_epoch','public_key_pin_sha256']);same(sv,gv,['core_installation_binding_sha256']);
  equal(cv.subject_sha256,s.digest);equal(cv.custody_public_receipt_sha256,r.digest);equal(cv.generation_preparation_sha256,g.digest);same(cv,sv,['custody_operation_id','core_installation_binding_sha256','policy_sha256']);
  equal(pv.subject_sha256,s.digest);equal(pv.custody_public_receipt_sha256,r.digest);equal(pv.admission_context_sha256,c.digest);same(pv,cv,['registration_operation_id','custody_operation_id']);equal(pv.expected_transcript,t.canonical_text);equal(tv.operator_admission_binding_sha256,c.digest);
  same(tv,cv,['registration_operation_id','challenge_id','challenge_nonce_sha256','core_installation_binding_sha256','registry_identity_sha256','registry_restore_policy_sha256','expected_registry_revision','policy_sha256','original_authorization_deadline_unix_ms']);same(tv,sv,['principal_id','principal_epoch','core_instance_id','installation_id','public_key_pin_sha256']);same(tv,rv,['public_key_jwk']);
  need((pv.original_signing_deadline_unix_ms as number)<=(cv.original_authorization_deadline_unix_ms as number),'original_mismatch');
  return Object.freeze({classification:CLASSIFICATION,generation:g,receipt:r,subject:s,context:c,proof:p,transcript:t});
}
export function checkBootstrapChain(input:unknown){return chain(snapshot(input,CHAIN));}
async function originalWithdrawal(v:Readonly<Record<string,string>>){
  const b=await chain(v),i=await decodeRecord(v.intent,'original_admission_intent'),w=await decodeRecord(v.withdrawal,'original_operation_withdrawal_preparation');const [iv,wv,pv,tv]=[i.values,w.values,b.proof.values,b.transcript.values];
  equal(iv.bootstrap_preparation_sha256,b.proof.digest);same(iv,pv,['subject_sha256','registration_operation_id','admission_context_sha256']);same(iv,tv,['registration_operation_id','challenge_id','challenge_nonce_sha256','expected_registry_revision','original_authorization_deadline_unix_ms']);
  equal(wv.original_admission_intent_sha256,i.digest);same(wv,iv,['subject_sha256','registration_operation_id','withdrawal_policy_sha256']);equal(wv.registration_challenge_id,iv.challenge_id);equal(wv.registration_challenge_nonce_sha256,iv.challenge_nonce_sha256);same(wv,tv,['registry_identity_sha256','registry_restore_policy_sha256']);
  need(wv.withdrawal_challenge_id!==iv.challenge_id&&wv.withdrawal_challenge_nonce_sha256!==iv.challenge_nonce_sha256&&wv.withdrawal_operation_id!==iv.registration_operation_id,'original_mismatch');
  return Object.freeze({...b,intent:i,withdrawal:w});
}
export function checkOriginalWithdrawal(input:unknown){return originalWithdrawal(snapshot(input,[...CHAIN,'intent','withdrawal']));}
export async function checkRetirementData(input:unknown){const v=snapshot(input,[...CHAIN,'intent','withdrawal','tombstone']),b=await originalWithdrawal(v),t=await decodeRecord(v.tombstone,'original_admission_retirement_tombstone');
  equal(t.values.original_admission_intent_sha256,b.intent.digest);equal(t.values.withdrawal_preparation_sha256,b.withdrawal.digest);same(t.values,b.intent.values,['subject_sha256','registration_operation_id']);same(t.values,b.withdrawal.values,['registration_challenge_id','registration_challenge_nonce_sha256','withdrawal_operation_id']);return Object.freeze({...b,tombstone:t});}
async function principal(v:Readonly<Record<string,string>>){const b=await chain(v),p=await decodeRecord(v.principal,'installation_principal_record');
  equal(p.values.subject_sha256,b.subject.digest);equal(p.values.bootstrap_preparation_sha256,b.proof.digest);equal(p.values.crypto_possession_body_sha256,b.transcript.body_sha256);equal(p.values.crypto_signing_input_sha256,b.transcript.signing_input_sha256);same(p.values,b.transcript.values,['registration_operation_id','challenge_id','public_key_pin_sha256','original_authorization_deadline_unix_ms']);return Object.freeze({...b,principal:p});}
export function checkPrincipalData(input:unknown){return principal(snapshot(input,[...CHAIN,'principal']));}
export async function checkDevicePairData(input:unknown){const v=snapshot(input,[...CHAIN,'principal','pair_join']),b=await principal(v),j=await decodeRecord(v.pair_join,'device_pair_join');equal(j.values.principal_record_sha256,b.principal.digest);equal(j.values.subject_sha256,b.principal.values.subject_sha256);return Object.freeze({...b,pair_join:j});}
export async function checkCommittedWithdrawalData(input:unknown){const v=snapshot(input,[...CHAIN,'principal','withdrawal']),b=await principal(v),w=await decodeRecord(v.withdrawal,'withdrawal_preparation');
  equal(w.values.principal_record_sha256,b.principal.digest);same(w.values,b.principal.values,['subject_sha256','registration_operation_id']);same(w.values,b.transcript.values,['registry_identity_sha256','registry_restore_policy_sha256']);need(w.values.challenge_id!==b.transcript.values.challenge_id&&w.values.challenge_nonce_sha256!==b.transcript.values.challenge_nonce_sha256&&w.values.withdrawal_operation_id!==b.transcript.values.registration_operation_id,'original_mismatch');return Object.freeze({...b,withdrawal:w});}
