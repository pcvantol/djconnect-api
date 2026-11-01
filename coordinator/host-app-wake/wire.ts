/** Separate candidate wire. No public-root admission or legacy token conversion. */
import {canonical, parseStrictJson} from '../../src/surface-push/wire';
export {canonical};
export const VERSION = 'djc-host-app-wake/1' as const;
export const ROLE = 'host_app_wake' as const;
export const PREFIX = '/v1/push/host-app-wake/';
export const BODY = '{"aps":{"content-available":1}}';
export type Kind = 'register'|'wake'|'revoke'|'status';
export class WakeError extends Error {constructor(readonly code:string, readonly status=400){super(code);}}
export function need(value:unknown,code='host_wake_invalid',status=400):asserts value {if(!value)throw new WakeError(code,status);}
export function integer(v:unknown,min=0,max=Number.MAX_SAFE_INTEGER):asserts v is number {
 need(typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=min&&v<=max);
}
export function id(v:unknown):asserts v is string {need(typeof v==='string'&&/^[A-Za-z0-9_-]{1,128}$/.test(v));}
export function exact(v:unknown,keys:readonly string[]):asserts v is Record<string,unknown> {
 need(v!==null&&typeof v==='object'&&!Array.isArray(v));
 need(Object.getPrototypeOf(v)===Object.prototype||Object.getPrototypeOf(v)===null);
 need(Reflect.ownKeys(v).length===keys.length);
 for(const k of keys){const d=Object.getOwnPropertyDescriptor(v,k);need(d&&Object.hasOwn(d,'value')&&d.enumerable);}
}
export interface Target {host_bundle_id:string; installation_id:string}
export function target(v:unknown):asserts v is Target {
 exact(v,['host_bundle_id','installation_id']);
 need(typeof v.host_bundle_id==='string'&&v.host_bundle_id.length<=200&&/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(v.host_bundle_id));id(v.installation_id);
}
export interface OriginalPurpose {
 version:typeof VERSION; purpose_id:string; token_role:typeof ROLE;
 owner_binding:string; device_binding:string; source_binding:string;
 target:Target; apns_environment:'sandbox'|'production'; platform:'ios'|'ipados';
 issued_at_ms:number; expires_at_ms:number; display_expires_at_ms:number; max_operations:number; max_wakes:number;
}
/** Structural constraints only; this function does not authenticate permission. */
export function original(value:unknown):OriginalPurpose {
 exact(value,['version','purpose_id','token_role','owner_binding','device_binding','source_binding','target','apns_environment','platform','issued_at_ms','expires_at_ms','display_expires_at_ms','max_operations','max_wakes']);
 need(value.version===VERSION&&value.token_role===ROLE);id(value.purpose_id);target(value.target);
 for(const k of ['owner_binding','device_binding','source_binding'])need(typeof value[k]==='string'&&/^[a-f0-9]{64}$/.test(value[k] as string));
 need(value.apns_environment==='sandbox'||value.apns_environment==='production');need(value.platform==='ios'||value.platform==='ipados');
 integer(value.issued_at_ms);integer(value.expires_at_ms,value.issued_at_ms+1);
 integer(value.display_expires_at_ms,value.expires_at_ms);
 integer(value.max_operations,1,256);integer(value.max_wakes,1,64);
 // Hard defensive ceiling, not a selected display-purpose lifetime.
 need(value.expires_at_ms-value.issued_at_ms<=8*3600000);
 return Object.freeze({...value,target:Object.freeze({...value.target})}) as unknown as OriginalPurpose;
}
export interface Input {version:typeof VERSION;purpose_id:string;operation_id:string;generation?:string;revision?:number;token_role?:typeof ROLE;target?:Target;apns_environment?:'sandbox'|'production';apns_token?:string;event?:'direct_rich_refresh'}
export function decode(kind:Kind,value:unknown):Input {
 const base=['version','purpose_id','operation_id'];
 exact(value,[...base,...(kind==='register'?['generation','revision','token_role','target','apns_environment','apns_token']:kind==='wake'?['generation','revision','event']:[])]);
 need(value.version===VERSION);id(value.purpose_id);id(value.operation_id);
 if(kind==='register'||kind==='wake'){id(value.generation);integer(value.revision,1,256);}
 if(kind==='register'){
  need(value.token_role===ROLE);target(value.target);need(value.apns_environment==='sandbox'||value.apns_environment==='production');
  need(typeof value.apns_token==='string'&&/^(?:[a-f0-9]{2}){16,2048}$/.test(value.apns_token));
 }
 if(kind==='wake')need(value.event==='direct_rich_refresh');
 return Object.freeze({...value,...(kind==='register'?{target:Object.freeze({...value.target as object})}:{})}) as unknown as Input;
}
export async function read(request:Request,kind:Kind):Promise<Input>{
 need(request.headers.get('content-type')?.trim().toLowerCase()==='application/json','host_wake_media',415);
 need(!request.headers.has('content-encoding'));const reader=request.body?.getReader();need(reader);const parts:Uint8Array[]=[];let size=0;
 try{for(;;){const p=await reader.read();if(p.done)break;size+=p.value.length;need(size<=8192,'host_wake_size',413);parts.push(p.value);}}catch(e){await reader.cancel().catch(()=>{});throw e;}
 const bytes=new Uint8Array(size);let offset=0;for(const p of parts){bytes.set(p,offset);offset+=p.length;}
 try{return decode(kind,parseStrictJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes)));}
 catch(e){if(e instanceof WakeError)throw e;throw new WakeError('host_wake_json');}
}
