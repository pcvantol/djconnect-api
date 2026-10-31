/** Closed PRIVATE API replies. Validation is DATA, never original authority. */
import {canonical} from '../../src/surface-push/wire';
import {sha256Hex} from '../../src/crypto';
import {exact,id,integer,need} from '../host-app-wake/wire';
import {RECEIVING_VERSION,decodeNativeOriginal,decodeNativeChallenge,checkNativeChallenge,type NativeOriginalData} from './wire';
import type {ServerRoute,ServerInput,NativeProofKind} from './server-wire';
const base=['version','authorization_id','issuer_operation_id','core_purpose_id','request_sha256','generation','revision','original_wake_issued_at_ms','original_wake_expires_at_ms','original_display_expires_at_ms','state'];
export type PrivateState='issued'|'pending'|'native_verified'|'withdrawn'|'expired'|'unknown';
export interface PrivateReply {version:typeof RECEIVING_VERSION;authorization_id:string;issuer_operation_id:string;core_purpose_id:string;request_sha256:string;generation:string;revision:number;original_wake_issued_at_ms:number;original_wake_expires_at_ms:number;original_display_expires_at_ms:number;state:PrivateState;[key:string]:unknown}
const native=['challenge_id','native_proof_kind','original_sha256'];
export const PRIVATE_ERRORS:Readonly<Record<number,readonly string[]>>=Object.freeze({
 400:['host_wake_invalid'],401:['host_wake_core_auth','host_wake_operator_hmac_required','auth_required'],
 403:['host_wake_principal_scope','host_wake_native_authority','host_wake_header_body_scope','host_wake_original_scope','host_wake_original_native_token','host_wake_native_proof_rejected'],
 404:['host_wake_receiving_route','host_wake_operator_route','host_wake_history_unknown'],
 409:['host_wake_intent_consumed','host_wake_intent_capacity_or_authority','host_wake_authorization_consumed_or_capacity','host_wake_issuer_consumed_or_capacity','host_wake_issuer_consumed','host_wake_native_job_consumed_or_capacity','host_wake_native_job_consumed','host_wake_native_job_expired','host_wake_transport_expired','host_wake_body_timeout','host_wake_cancelled'],
 413:['host_wake_size'],415:['host_wake_media'],503:['host_wake_receiving_unavailable','host_wake_authorization_unavailable','host_wake_native_enrollment_unavailable','host_wake_native_policy_unavailable','host_wake_native_attestation_unavailable','host_wake_native_deployment_mismatch']
});
export function privateError(code:string,status:number){
 if(!PRIVATE_ERRORS[status]?.includes(code)){status=503;code='host_wake_receiving_unavailable';}
 return new Response(JSON.stringify({version:RECEIVING_VERSION,success:false,error:code}),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'}});
}
export function decodePrivateError(status:number,value:unknown){exact(value,['version','success','error']);need(value.version===RECEIVING_VERSION&&value.success===false&&typeof value.error==='string'&&PRIVATE_ERRORS[status]?.includes(value.error));return Object.freeze({...value});}
function proofKind(v:unknown){need(v==='app_attest_attestation'||v==='app_attest_assertion');}
function hash(v:unknown){need(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v));}
export function privateBase(input:ServerInput,o:Readonly<NativeOriginalData>,requestHash:string,state:PrivateState){
 return {version:RECEIVING_VERSION,authorization_id:input.authorization_id,issuer_operation_id:input.issuer_operation_id,core_purpose_id:input.core_purpose_id,request_sha256:requestHash,generation:o.generation,revision:o.revision,original_wake_issued_at_ms:o.original_wake_issued_at_ms,original_wake_expires_at_ms:o.original_wake_expires_at_ms,original_display_expires_at_ms:o.original_display_expires_at_ms,state};
}
/** Every response is checked against the caller's exact authenticated private
 * request and SAME retained original tuple. It cannot initialize that tuple. */
export async function decodePrivateReply(route:ServerRoute,input:ServerInput,retainedOriginal:Readonly<NativeOriginalData>,requestHash:string,value:unknown,retainedProofKind?:NativeProofKind):Promise<Readonly<PrivateReply>>{
 need(value!==null&&typeof value==='object'&&!Array.isArray(value));const v=value as Record<string,unknown>;
 const extra=route==='issuer/issue'?['purpose_id','credential_state','credential','expires_at_ms','native_proof_kind','registration_mode','original']:
  route==='issuer/status'?['purpose_id','credential_state']:
  route==='issuer/withdraw'?[]:
  route==='native/challenge'?['native_proof_kind','original','challenge','canonical_transcript_utf8','client_data_sha256']:
  [...native,...(v.state==='native_verified'?['native_verified_at_ms']:[])];
 exact(v,[...base,...extra]);need(v.version===RECEIVING_VERSION);for(const k of ['authorization_id','issuer_operation_id','core_purpose_id','generation'])id(v[k]);hash(v.request_sha256);
 const o=decodeNativeOriginal(retainedOriginal);need(v.authorization_id===input.authorization_id&&v.issuer_operation_id===input.issuer_operation_id&&v.core_purpose_id===input.core_purpose_id&&v.core_purpose_id===o.core_purpose_id&&v.request_sha256===requestHash&&v.generation===o.generation&&v.revision===o.revision);
 for(const k of ['original_wake_issued_at_ms','original_wake_expires_at_ms','original_display_expires_at_ms'] as const)need(v[k]===o[k]);
 const states=route==='issuer/issue'?['issued']:route==='issuer/status'?['pending','issued','withdrawn','expired','unknown']:route==='issuer/withdraw'?['withdrawn','expired','unknown']:route==='native/challenge'?['pending']:['pending','native_verified','withdrawn','expired','unknown'];need(typeof v.state==='string'&&states.includes(v.state));
 if(route.startsWith('native/')){need(retainedProofKind==='app_attest_assertion'||retainedProofKind==='app_attest_attestation');need(v.native_proof_kind===retainedProofKind);if(route==='native/complete')need(input.native_proof?.kind===retainedProofKind);}
 if(route==='issuer/issue'){
  need(canonical(decodeNativeOriginal(input.original))===canonical(o));
  id(v.purpose_id);need(v.registration_mode==='single_original_no_rotation');need(v.credential_state==='available'&&typeof v.credential==='string'&&/^djchw_[A-Za-z0-9_-]{43}$/.test(v.credential)&&v.expires_at_ms===o.original_wake_expires_at_ms);proofKind(v.native_proof_kind);need(canonical(decodeNativeOriginal(v.original))===canonical(o));
 }else if(route==='issuer/status'){id(v.purpose_id);need(v.credential_state==='unavailable');}
 else if(route==='native/challenge'){
  proofKind(v.native_proof_kind);need(canonical(decodeNativeOriginal(v.original))===canonical(o));const c=decodeNativeChallenge(v.challenge,o);need(c.challenge_id===input.challenge_id);need(typeof v.canonical_transcript_utf8==='string'&&typeof v.client_data_sha256==='string');await checkNativeChallenge(o,c,v.canonical_transcript_utf8,v.client_data_sha256);
 }else if(route.startsWith('native/')){
  need(v.challenge_id===input.challenge_id);proofKind(v.native_proof_kind);hash(v.original_sha256);need(v.original_sha256===await sha256Hex(canonical(o)));if(v.state==='native_verified')integer(v.native_verified_at_ms,o.original_wake_issued_at_ms,o.original_wake_expires_at_ms-1);
 }
 return Object.freeze({...v,...(Object.hasOwn(v,'original')?{original:decodeNativeOriginal(v.original)}:{}),...(route==='native/challenge'?{challenge:decodeNativeChallenge(v.challenge,o)}:{})}) as Readonly<PrivateReply>;
}
