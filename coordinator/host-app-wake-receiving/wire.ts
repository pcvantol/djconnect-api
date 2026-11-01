/** Closed receiving candidate DATA. Decoding is never original/native authority. */
import {canonical,parseStrictJson} from '../../src/surface-push/wire';
import {exact,id,integer,need,target,type Target} from '../host-app-wake/wire';
export const RECEIVING_VERSION='djc-host-app-wake-receiving/1' as const;
export const NATIVE_VERSION='djc-host-app-wake-native/1' as const;
export const NATIVE_DOMAIN='DJC-HOST-APP-WAKE-TARGET-REGISTER-V1\n';
export const OPERATOR_AUTHORIZE='/v1/push/host-app-wake/operator/authorize';
export const OPERATOR_WITHDRAW='/v1/push/host-app-wake/operator/withdraw';
export const MAX_BODY_BYTES=16384;
const hashes=['paired_subject_binding_sha256','owner_binding','device_binding','source_binding','selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256'] as const;
function hash(v:unknown){need(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v));}
function environment(v:unknown){need(v==='sandbox'||v==='production');}
function platform(v:unknown){need(v==='ios'||v==='ipados');}
export interface OperatorAuthorizationData {
 version:typeof RECEIVING_VERSION;method:'POST';route:typeof OPERATOR_AUTHORIZE;action:'authorize';
 operation_id:string;authorization_id:string;core_install_token_record_id:string;ha_install_id:string;
 paired_subject_binding_sha256:string;owner_binding:string;device_binding:string;source_binding:string;
 selected_ha_origin_sha256:string;identity_policy_sha256:string;deployment_policy_sha256:string;
 target:Target;platform:'ios'|'ipados';apns_environment:'sandbox'|'production';native_key_ref:string;
 max_original_purpose_ms:number;max_operations:number;max_reserved_sends:number;
 original_authorization_issued_at_ms:number;original_authorization_expires_at_ms:number;
}
const operatorKeys=['version','method','route','action','operation_id','authorization_id','core_install_token_record_id','ha_install_id',...hashes,'target','platform','apns_environment','native_key_ref','max_original_purpose_ms','max_operations','max_reserved_sends','original_authorization_issued_at_ms','original_authorization_expires_at_ms'];
export function decodeOperatorAuthorization(value:unknown):Readonly<OperatorAuthorizationData>{
 exact(value,operatorKeys);need(value.version===RECEIVING_VERSION&&value.method==='POST'&&value.route===OPERATOR_AUTHORIZE&&value.action==='authorize');
 for(const k of ['operation_id','authorization_id','core_install_token_record_id','ha_install_id','native_key_ref'])id(value[k]);
 for(const k of hashes)hash(value[k]);target(value.target);platform(value.platform);environment(value.apns_environment);
 integer(value.max_original_purpose_ms,1,8*3600000);integer(value.max_operations,1,256);integer(value.max_reserved_sends,1,64);
 integer(value.original_authorization_issued_at_ms);integer(value.original_authorization_expires_at_ms,value.original_authorization_issued_at_ms+1);
 return Object.freeze({...value,target:Object.freeze({...value.target})}) as unknown as Readonly<OperatorAuthorizationData>;
}
export interface OperatorWithdrawalData {version:typeof RECEIVING_VERSION;method:'POST';route:typeof OPERATOR_WITHDRAW;action:'withdraw';operation_id:string;authorization_id:string}
export function decodeOperatorWithdrawal(value:unknown):Readonly<OperatorWithdrawalData>{
 exact(value,['version','method','route','action','operation_id','authorization_id']);
 need(value.version===RECEIVING_VERSION&&value.method==='POST'&&value.route===OPERATOR_WITHDRAW&&value.action==='withdraw');id(value.operation_id);id(value.authorization_id);
 return Object.freeze({...value}) as unknown as Readonly<OperatorWithdrawalData>;
}
/** DATA bounds only. Authentic enrollment must independently match the actual SDK
 * key identifier and its policy-specific decoded length; parsing is not admission. */
function nativeKeyId(v:unknown):asserts v is string {
 need(typeof v==='string'&&v.length<=1368&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v));
 const raw=atob(v);need(raw.length>=1&&raw.length<=1024&&btoa(raw)===v);
}
function uuid(v:unknown):asserts v is string {need(typeof v==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v));}
export interface NativeOriginalData {
 version:typeof NATIVE_VERSION;core_purpose_id:string;operation_id:string;generation:string;revision:number;
 token_role:'host_app_wake';target:Target;platform:'ios'|'ipados';apns_environment:'sandbox'|'production';
 paired_subject_binding_sha256:string;owner_binding:string;device_binding:string;source_binding:string;
 selected_ha_origin_sha256:string;identity_policy_sha256:string;deployment_policy_sha256:string;
 native_key_id_b64:string;native_token_sha256:string;
 original_wake_issued_at_ms:number;original_wake_expires_at_ms:number;original_display_expires_at_ms:number;
}
const originalKeys=['version','core_purpose_id','operation_id','generation','revision','token_role','target','platform','apns_environment',...hashes,'native_key_id_b64','native_token_sha256','original_wake_issued_at_ms','original_wake_expires_at_ms','original_display_expires_at_ms'];
export function decodeNativeOriginal(value:unknown):Readonly<NativeOriginalData>{
 exact(value,originalKeys);need(value.version===NATIVE_VERSION&&value.token_role==='host_app_wake');
 for(const k of ['core_purpose_id','generation'])id(value[k]);uuid(value.operation_id);nativeKeyId(value.native_key_id_b64);
 integer(value.revision,1,256);target(value.target);platform(value.platform);environment(value.apns_environment);
 for(const k of [...hashes,'native_token_sha256'])hash(value[k]);
 integer(value.original_wake_issued_at_ms);integer(value.original_wake_expires_at_ms,value.original_wake_issued_at_ms+1);
 integer(value.original_display_expires_at_ms,value.original_wake_expires_at_ms);need(value.original_wake_expires_at_ms-value.original_wake_issued_at_ms<=8*3600000);
 return Object.freeze({...value,target:Object.freeze({...value.target})}) as unknown as Readonly<NativeOriginalData>;
}
export interface NativeChallengeData {challenge_id:string;nonce_b64url:string;captured_at_ms:number;expires_at_ms:number}
export function decodeNativeChallenge(value:unknown,original:Readonly<NativeOriginalData>):Readonly<NativeChallengeData>{
 exact(value,['challenge_id','nonce_b64url','captured_at_ms','expires_at_ms']);uuid(value.challenge_id);
 need(typeof value.nonce_b64url==='string'&&/^[A-Za-z0-9_-]{43}$/.test(value.nonce_b64url));
 const raw=atob(value.nonce_b64url.replaceAll('-','+').replaceAll('_','/')+'=');
 need(raw.length===32&&btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')===value.nonce_b64url);
 integer(value.captured_at_ms,original.original_wake_issued_at_ms);integer(value.expires_at_ms,value.captured_at_ms+1,original.original_wake_expires_at_ms);
 need(value.expires_at_ms-value.captured_at_ms<=30000);
 return Object.freeze({...value}) as unknown as Readonly<NativeChallengeData>;
}
export function nativeSigningData(originalValue:unknown,challengeValue:unknown):Readonly<{canonical_utf8:string;client_data:Uint8Array}>{
 const original=decodeNativeOriginal(originalValue),challenge=decodeNativeChallenge(challengeValue,original);
 const canonical_utf8=canonical({original,challenge});
 const client_data=new TextEncoder().encode(NATIVE_DOMAIN+canonical_utf8);need(client_data.byteLength<=8192);
 return Object.freeze({canonical_utf8,client_data});
}
/** Only the canonical transcript representation is accepted at this boundary.
 * This rejects lexical -0, 1.0, 1e0, escaped keys, whitespace and BOM before
 * those representations can be silently normalized by another JSON runtime. */
export function parseNativeTranscript(text:string):Readonly<{original:Readonly<NativeOriginalData>;challenge:Readonly<NativeChallengeData>}>{
 need(typeof text==='string'&&new TextEncoder().encode(text).length<=8192);
 const value=parseStrictJson(text);exact(value,['original','challenge']);
 const original=decodeNativeOriginal(value.original),challenge=decodeNativeChallenge(value.challenge,original);
 need(nativeSigningData(original,challenge).canonical_utf8===text,'host_wake_noncanonical_transcript');
 return Object.freeze({original,challenge});
}
/** Apple receives original tuple AND nonce, recomputes bytes from its own
 * admitted pre-await context, and compares; an opaque server hash is insufficient. */
export async function checkNativeChallenge(originalValue:unknown,challengeValue:unknown,advertisedCanonical:string,advertisedHash:string):Promise<Readonly<{canonical_utf8:string;client_data:Uint8Array;client_data_sha256:string}>>{
 const data=nativeSigningData(originalValue,challengeValue);need(typeof advertisedCanonical==='string'&&advertisedCanonical===data.canonical_utf8);hash(advertisedHash);
 const bytes=await crypto.subtle.digest('SHA-256',data.client_data);
 const actual=[...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');need(actual===advertisedHash);
 return Object.freeze({...data,client_data_sha256:actual});
}
/** Digest actual APNs token bytes, never their hexadecimal text representation. */
export async function nativeTokenSha256(bytes:Uint8Array):Promise<string>{
 need(bytes instanceof Uint8Array&&bytes.length>=16&&bytes.length<=2048);
 const snapshot=Uint8Array.from(bytes);
 return [...new Uint8Array(await crypto.subtle.digest('SHA-256',snapshot))].map(x=>x.toString(16).padStart(2,'0')).join('');
}
export async function checkNativeToken(originalValue:unknown,bytes:Uint8Array):Promise<void>{
 const original=decodeNativeOriginal(originalValue);need(await nativeTokenSha256(bytes)===original.native_token_sha256);
}
export async function boundedJson(request:Request):Promise<{value:unknown;raw:Uint8Array<ArrayBuffer>} >{
 need(request.headers.get('content-type')?.trim().toLowerCase()==='application/json','host_wake_media',415);need(!request.headers.has('content-encoding'));
 const reader=request.body?.getReader();need(reader);const chunks:Uint8Array[]=[];let size=0;
 try{for(;;){const p=await reader.read();if(p.done)break;size+=p.value.length;need(size<=MAX_BODY_BYTES,'host_wake_size',413);chunks.push(p.value);}}catch(e){await reader.cancel().catch(()=>{});throw e;}
 const raw=new Uint8Array(size);let offset=0;for(const c of chunks){raw.set(c,offset);offset+=c.length;}
 return {value:parseStrictJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw)),raw};
}
