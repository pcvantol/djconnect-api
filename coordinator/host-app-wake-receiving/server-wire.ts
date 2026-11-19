/** Private Core-to-API receiving DTOs. These are NOT Apple-to-Core DTOs. */
import {exact,id,need} from '../host-app-wake/wire';
import {decodeNativeOriginal,RECEIVING_VERSION,type NativeOriginalData} from './wire';
export const SERVER_PREFIX='/v1/push/host-app-wake/';
export const SERVER_ROUTES=['issuer/issue','issuer/status','issuer/withdraw','native/challenge','native/complete','native/status'] as const;
export type ServerRoute=typeof SERVER_ROUTES[number];
export type NativeProofKind='app_attest_attestation'|'app_attest_assertion';
export interface NativeProofData {kind:NativeProofKind;bytes_b64:string}
export interface ServerInput {version:typeof RECEIVING_VERSION;authorization_id:string;issuer_operation_id:string;core_purpose_id:string;original?:Readonly<NativeOriginalData>;challenge_id?:string;native_proof?:Readonly<NativeProofData>}
export function proof(value:unknown):Readonly<NativeProofData>{
 exact(value,['kind','bytes_b64']);need(value.kind==='app_attest_attestation'||value.kind==='app_attest_assertion');
 need(typeof value.bytes_b64==='string'&&value.bytes_b64.length<=12288&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.bytes_b64));
 const raw=atob(value.bytes_b64);need(raw.length>=1&&raw.length<=9216&&btoa(raw)===value.bytes_b64);
 return Object.freeze({...value}) as unknown as Readonly<NativeProofData>;
}
export function decodeServer(route:ServerRoute,value:unknown):Readonly<ServerInput>{
 need(SERVER_ROUTES.includes(route));const base=['version','authorization_id','issuer_operation_id','core_purpose_id'];
 exact(value,[...base,...(route==='issuer/issue'?['original']:route.startsWith('native/')?['challenge_id',...(route==='native/complete'?['native_proof']:[])]:[])]);
 need(value.version===RECEIVING_VERSION);for(const k of ['authorization_id','issuer_operation_id','core_purpose_id'])id(value[k]);
 if(route.startsWith('native/'))need(typeof value.challenge_id==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.challenge_id));
 const original=route==='issuer/issue'?decodeNativeOriginal(value.original):undefined;if(original)need(original.core_purpose_id===value.core_purpose_id);
 const native_proof=route==='native/complete'?proof(value.native_proof):undefined;
 return Object.freeze({...value,...(original?{original}:{}),...(native_proof?{native_proof}:{})}) as unknown as Readonly<ServerInput>;
}
export function serverRoute(request:Request):ServerRoute{
 const u=new URL(request.url);need(request.method==='POST'&&u.protocol==='https:'&&!request.url.includes('?')&&!request.url.includes('#'),'host_wake_receiving_route',404);
 need(!request.headers.has('origin')&&!request.headers.has('cookie')&&!request.headers.has('x-djconnect-device-id')&&!request.headers.has('x-djconnect-client-type'),'host_wake_server_transport',403);
 const route=u.pathname.startsWith(SERVER_PREFIX)?u.pathname.slice(SERVER_PREFIX.length):'';need(SERVER_ROUTES.includes(route as ServerRoute),'host_wake_receiving_route',404);return route as ServerRoute;
}
