/** Private production-prefix composition. UTC observation is not admission. */
import type {AppEnv} from '../types';
import {createReceivingService,type ReceivingOptions} from '../../coordinator/host-app-wake-receiving/service';
import {privateError} from '../../coordinator/host-app-wake-receiving/server-reply';
const PREFIX='/v1/push/host-app-wake';
// Source-selected mount. Every request still requires its existing private
// principal/custodian and saved original/native policy gates.
const PRIVATE_RECEIVING_HTTP_ENABLED=true as boolean;
export interface OriginalReceivingPorts {capturedAt:number;observeUTC:()=>number;fetcher:typeof fetch;capacity:number}
/** Explicit trusted composition port. No default clock/transport/currentness.
 * Request identity binds the original caller capture; every later clock read
 * remains an actual UTC observation, even before the first await.
 * Existing request-window regression/expiry/cancellation gates remain owning. */
export function receiveOriginalPrivateRequest(request:Request,env:AppEnv,ports:OriginalReceivingPorts):Promise<Response>{
 if(!Number.isSafeInteger(ports.capturedAt)||ports.capturedAt<0||typeof ports.observeUTC!=='function'||typeof ports.fetcher!=='function')return Promise.resolve(privateError('host_wake_receiving_unavailable',503));
 const options:ReceivingOptions={env,capacity:ports.capacity,fetcher:ports.fetcher,now:ports.observeUTC,originalRequestCapture:Object.freeze({request,capturedAt:ports.capturedAt})};
 try{const service=createReceivingService(options);return service.handle(request).finally(()=>service.close());}
 catch{return Promise.resolve(privateError('host_wake_receiving_unavailable',503));}
}
/** Root caller invokes this synchronously BEFORE its first unrelated await.
 * Other namespaces are untouched; no caller/env boolean selects this mount. */
export function dispatchPrivateReceivingRequest(request:Request,env:unknown,observeUTC:()=>number,fetcher:typeof fetch):Promise<Response>|undefined{
 const path=new URL(request.url).pathname;if(path!==PREFIX&&!path.startsWith(PREFIX+'/'))return undefined;
 if(!PRIVATE_RECEIVING_HTTP_ENABLED)return Promise.resolve(privateError('host_wake_receiving_unavailable',503));
 // Actual platform UTC only; no claim about Core/Apple clock qualification.
 try{const capturedAt=observeUTC();return receiveOriginalPrivateRequest(request,env as AppEnv,{capturedAt,observeUTC,fetcher,capacity:256});}
 catch{return Promise.resolve(privateError('host_wake_receiving_unavailable',503));}
}
