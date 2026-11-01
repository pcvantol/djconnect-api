/** Closed custodian-signed first-enrollment policy DATA. Parsing is not a grant. */
import {canonical} from '../../src/surface-push/wire';
import {exact,id,integer,need,target,type Target} from '../host-app-wake/wire';
import {RECEIVING_VERSION,type OperatorAuthorizationData,type NativeOriginalData} from './wire';
export const OPERATOR_NATIVE_POLICY='/v1/push/host-app-wake/operator/native-policy';
export const OPERATOR_NATIVE_WITHDRAW='/v1/push/host-app-wake/operator/native-policy/withdraw';
const hashes=['paired_subject_binding_sha256','owner_binding','device_binding','source_binding','selected_ha_origin_sha256','identity_policy_sha256','deployment_policy_sha256'] as const;
export interface NativePolicyScope {paired_subject_binding_sha256:string;owner_binding:string;device_binding:string;source_binding:string;selected_ha_origin_sha256:string;identity_policy_sha256:string;deployment_policy_sha256:string;target:Target;platform:'ios'|'ipados';apns_environment:'sandbox'|'production'}
interface NativePolicyBase {
 version:typeof RECEIVING_VERSION;method:'POST';route:typeof OPERATOR_NATIVE_POLICY;action:'native_policy';
 operation_id:string;authorization_id:string;native_key_ref:string;native_key_id_b64:string;
 app_identifier:string;apns_team_id:string;app_attest_environment:'development'|'production';bundle_version:string;
 signed_host_artifact_sha256:string;signed_environment_receipt_sha256:string;scope:Readonly<NativePolicyScope>;
 original_policy_issued_at_ms:number;original_policy_expires_at_ms:number;
}
export type NativePolicy=NativePolicyBase & ({profile:'host_wake_apple_properties_attestation_v2';launch_validation_category_b64:string}|{profile:'host_wake_apple_properties_attestation_v3';allowed_launch_validation_categories_b64:readonly string[]});
export interface NativePolicyWithdrawal {version:typeof RECEIVING_VERSION;method:'POST';route:typeof OPERATOR_NATIVE_WITHDRAW;action:'native_policy_withdraw';operation_id:string;native_key_ref:string}
const digest=(v:unknown)=>need(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v));
export function strictNativeBase64(v:unknown,size:number):asserts v is string{
 need(typeof v==='string'&&v.length===4*Math.ceil(size/3)&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(v));const raw=atob(v);need(raw.length===size&&btoa(raw)===v);
}
/** Selected iOS/iPadOS distributions only, UInt32 little endian as signed by
 * Apple's properties extension. No OS, Developer-ID/Mac or unknown category. */
export function decodeLaunchCategory(value:unknown):string{
 strictNativeBase64(value,4);const raw=Uint8Array.from(atob(value),c=>c.charCodeAt(0));need([2,3,4,5].includes(new DataView(raw.buffer).getUint32(0,true)));return value;
}
export function decodeNativePolicy(value:unknown):Readonly<NativePolicy>{
 need(value!==null&&typeof value==='object'&&!Array.isArray(value));
 const v3=(value as Record<string,unknown>).profile==='host_wake_apple_properties_attestation_v3';
 exact(value,['version','method','route','action','operation_id','authorization_id','native_key_ref','native_key_id_b64','profile','app_identifier','apns_team_id','app_attest_environment','bundle_version',...(v3?['allowed_launch_validation_categories_b64']:['launch_validation_category_b64']),'signed_host_artifact_sha256','signed_environment_receipt_sha256','scope','original_policy_issued_at_ms','original_policy_expires_at_ms']);
 need(value.version===RECEIVING_VERSION&&value.method==='POST'&&value.route===OPERATOR_NATIVE_POLICY&&value.action==='native_policy'&&(value.profile==='host_wake_apple_properties_attestation_v2'||v3));
 for(const k of ['operation_id','authorization_id','native_key_ref'])id(value[k]);strictNativeBase64(value.native_key_id_b64,32);if(v3){
  const list=value.allowed_launch_validation_categories_b64;need(Array.isArray(list)&&list.length>=1&&list.length<=4);
  let previous=0;for(const item of list){const raw=atob(decodeLaunchCategory(item)),number=raw.charCodeAt(0);need(number>previous);previous=number;}
 }else decodeLaunchCategory(value.launch_validation_category_b64);
 digest(value.signed_host_artifact_sha256);digest(value.signed_environment_receipt_sha256);exact(value.scope,[...hashes,'target','platform','apns_environment']);const s=value.scope;for(const k of hashes)digest(s[k]);target(s.target);need((s.platform==='ios'||s.platform==='ipados')&&(s.apns_environment==='sandbox'||s.apns_environment==='production'));
 need(typeof value.apns_team_id==='string'&&/^[A-Z0-9]{10}$/.test(value.apns_team_id)&&typeof value.app_identifier==='string'&&value.app_identifier===value.apns_team_id+'.'+s.target.host_bundle_id);
 need(value.app_attest_environment==='development'||value.app_attest_environment==='production');need(typeof value.bundle_version==='string'&&/^[0-9]{1,20}(?:\.[0-9]{1,20}){0,2}$/.test(value.bundle_version));integer(value.original_policy_issued_at_ms);integer(value.original_policy_expires_at_ms,value.original_policy_issued_at_ms+1);
 return Object.freeze({...value,...(v3?{allowed_launch_validation_categories_b64:Object.freeze([...(value.allowed_launch_validation_categories_b64 as string[])])}:{}),scope:Object.freeze({...s,target:Object.freeze({...s.target})})}) as unknown as Readonly<NativePolicy>;
}
export function decodeNativePolicyWithdrawal(value:unknown):Readonly<NativePolicyWithdrawal>{
 exact(value,['version','method','route','action','operation_id','native_key_ref']);need(value.version===RECEIVING_VERSION&&value.method==='POST'&&value.route===OPERATOR_NATIVE_WITHDRAW&&value.action==='native_policy_withdraw');id(value.operation_id);id(value.native_key_ref);return Object.freeze({...value}) as unknown as Readonly<NativePolicyWithdrawal>;
}
export function matchNativePolicy(policy:Readonly<NativePolicy>,value:OperatorAuthorizationData|NativeOriginalData){
 for(const k of [...hashes,'platform','apns_environment'] as const)need(policy.scope[k]===value[k],'host_wake_native_authority',403);need(canonical(policy.scope.target)===canonical(value.target),'host_wake_native_authority',403);
 if('native_key_ref' in value)need(policy.native_key_ref===value.native_key_ref&&policy.authorization_id===value.authorization_id&&policy.original_policy_issued_at_ms>=value.original_authorization_issued_at_ms&&policy.original_policy_expires_at_ms<=value.original_authorization_expires_at_ms,'host_wake_native_authority',403);
 else need(policy.native_key_id_b64===value.native_key_id_b64&&value.original_wake_issued_at_ms>=policy.original_policy_issued_at_ms&&value.original_wake_expires_at_ms<=policy.original_policy_expires_at_ms,'host_wake_native_authority',403);
}
/** A custodian's initial set never becomes an assertion allowlist. */
export function requireNativeCategory(policy:Readonly<NativePolicy>,observed:string){
 decodeLaunchCategory(observed);need(policy.profile==='host_wake_apple_properties_attestation_v2'?policy.launch_validation_category_b64===observed:policy.allowed_launch_validation_categories_b64.includes(observed),'host_wake_native_authority',403);return observed;
}
export function assertionPolicyForNative(policy:Readonly<NativePolicy>,observed:string){
 return canonical({profile:'host_wake_apple_assertion_properties_v2',app_identifier:policy.app_identifier,bundle_version:policy.bundle_version,launch_validation_category_b64:requireNativeCategory(policy,observed)});
}
