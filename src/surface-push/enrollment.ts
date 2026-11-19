/** Internal source factory only. Public namespace remains compiled closed. No provider IO. */
import { requireAdminAuth } from "../auth";
import { base64Url, sha256Hex, timingSafeEqualString } from "../crypto";
import { HttpError } from "../http";
import type { AppEnv } from "../types";
import { canonical, need, SurfaceError } from "./wire";
import { bytes, closed, id, operationDeadline, publicKey, readBody } from "./issuer-wire";
import { authorize, bindings, ENROLLMENT_DOMAIN, ENROLLMENT_PREFIX, redeem, redemptionBytes } from "./enrollment-wire";

interface Row {
 id:string; token_hash:string; authorize_operation_id:string; nonce_hash:string; action_key:string;
 consent_digest:string; request_hash:string; key_thumbprint:string; scope_digest:string;
 delegation_id:string; enrollment_operation_id:string; expires_at:number; grant_expires_at:number;
 state:string; claim_id:string; outcome:string; revoked_at:number|null;
}
function reply(body:unknown,status=200) { return new Response(JSON.stringify(body),{status,headers:{
 "content-type":"application/json; charset=utf-8","cache-control":"no-store","referrer-policy":"no-referrer","x-content-type-options":"nosniff"}}); }
// Actual SQLite wall time additionally fences a delayed D1 transaction, not a newly sampled lease.
const SQL_NOW = "CAST(unixepoch('subsec') * 1000 AS INTEGER)";
export interface SurfaceEnrollmentOptions { env:AppEnv; now?:()=>number; isCurrent?:()=>boolean }
export function createSurfaceEnrollment(options:SurfaceEnrollmentOptions) {
 const originalEnv=options.env, originalNow=options.now, originalCurrent=options.isCurrent;
 const db=originalEnv.DB, secret=originalEnv.DJCONNECT_RELAY_SECRET;
 const authEnv=Object.freeze({DJCONNECT_RELAY_SECRET:secret}) as AppEnv;
 let highWater=0,retired=false;
 const same=()=>options.env===originalEnv&&options.now===originalNow&&options.isCurrent===originalCurrent&&
  originalEnv.DB===db&&originalEnv.DJCONNECT_RELAY_SECRET===secret;
 const guard=(signal?:AbortSignal)=>{
  let active=false;
  try {active=!retired&&same()&&(originalCurrent?.()??true)&&!retired&&same();} catch {active=false;}
  if(!active)retired=true; // An observed retirement cannot be undone by restoring values.
  need(active,"surface_service_unavailable",503);
  need(!signal?.aborted,"surface_operation_cancelled",409);
 };
 const now=()=>{
  guard();let n:number;try {n=(originalNow??Date.now)();} catch(error) {retired=true;throw error;}
  guard();const qualified=Number.isSafeInteger(n)&&n>=highWater&&n>=0;
  if(!qualified)retired=true;need(qualified,"surface_clock_unqualified",503);highWater=n;return n;
 };
 const checked=async<T>(signal:AbortSignal,work:()=>Promise<T>):Promise<T>=>{
  guard(signal); // The thunk must not start body/auth/crypto/DB work before this guard.
  try {const value=await work();guard(signal);return value;} catch(error) {guard(signal);throw error;}
 };
 const commit=(signal:AbortSignal,statements:()=>D1PreparedStatement[])=>checked(signal,()=>{
  const batch=statements();guard(signal);return db.batch(batch); // Final no-await guard, then submit.
 });
 const row=(name:string,signal:AbortSignal)=>checked(signal,()=>db.prepare("SELECT * FROM surface_enrollment_authorizations WHERE id=?").bind(name).first<Row>());
 async function authorizeOnce(value:unknown,signal:AbortSignal) {
  const input=authorize(value,now()); await checked(signal,()=>publicKey(input.enrollment.public_key));
  const b=await checked(signal,()=>bindings(input.consent,input.enrollment)), clock=now();
  const end=Math.min(input.consent.expires_at_ms,input.enrollment.policy.original_grant_expires_at_ms,
   operationDeadline(input.operation_id,clock),operationDeadline(input.enrollment.operation_id,clock));
  need(end>clock,"operation_expired",409);
  const hash=await checked(signal,()=>sha256Hex(canonical([ENROLLMENT_DOMAIN,"operator/authorize",input])));
  const token="djce_"+base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer), tokenHash=await checked(signal,()=>sha256Hex(token)), claim=crypto.randomUUID();
  const current=now(); need(current<end,"operation_expired",409);need(!signal.aborted,"surface_operation_cancelled",409);
  await commit(signal,()=>[
   db.prepare("INSERT OR IGNORE INTO surface_enrollment_operator_operations VALUES(?,?,?,'authorize',?,'pending')").bind(input.operation_id,hash,input.authorization_id,claim),
   db.prepare(`INSERT OR IGNORE INTO surface_enrollment_authorizations
    (id,token_hash,authorize_operation_id,nonce_hash,action_key,consent_digest,request_hash,key_thumbprint,scope_digest,delegation_id,enrollment_operation_id,expires_at,grant_expires_at,state,claim_id,outcome,created_at)
    SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,'available',?,'authorized',? WHERE
    EXISTS(SELECT 1 FROM surface_enrollment_operator_operations WHERE operation_id=? AND request_hash=? AND claim_id=? AND outcome='pending') AND
    NOT EXISTS(SELECT 1 FROM surface_enrollment_operator_operations WHERE authorization_id=? AND kind='revoke' AND outcome='revoked') AND ?>${SQL_NOW}`)
    .bind(input.authorization_id,tokenHash,input.operation_id,b.nonce,b.action,b.consent,b.request,b.key,b.scope,input.enrollment.delegation_id,input.enrollment.operation_id,end,input.enrollment.policy.original_grant_expires_at_ms,claim,current,input.operation_id,hash,claim,input.authorization_id,end),
   db.prepare(`UPDATE surface_enrollment_operator_operations SET outcome=CASE WHEN EXISTS(SELECT 1 FROM surface_enrollment_authorizations WHERE id=? AND authorize_operation_id=? AND claim_id=?) THEN 'authorized' ELSE 'conflict' END WHERE operation_id=? AND claim_id=?`)
    .bind(input.authorization_id,input.operation_id,claim,input.operation_id,claim),
  ]);
  const op=await checked(signal,()=>db.prepare("SELECT request_hash,outcome FROM surface_enrollment_operator_operations WHERE operation_id=?").bind(input.operation_id).first<{request_hash:string;outcome:string}>());
  need(op?.request_hash===hash&&op.outcome==="authorized","surface_operation_conflict",409);
  const saved=await row(input.authorization_id,signal); need(saved,"surface_operation_conflict",409);
  const owns=saved.claim_id===claim&&saved.state==="available"&&saved.revoked_at===null&&saved.expires_at>now();
  guard(signal);return reply({contract_version:1,success:owns,authorization_id:saved.id,operation_id:input.operation_id,
   request_hash:saved.request_hash,consent_digest:saved.consent_digest,key_thumbprint:saved.key_thumbprint,scope_digest:saved.scope_digest,
   expires_at_ms:saved.expires_at,state:owns?"authorized":"unknown",credential_state:owns?"available":"unavailable",replayed:!owns,...(owns?{credential:token}:{})},owns?200:202);
 }
 async function redeemOnce(value:unknown,request:Request) {
  const envelope=redeem(value,now()), p=envelope.payload, e=p.enrollment;
  const bearer=request.headers.get("authorization")??"";
  need(/^Bearer djce_[A-Za-z0-9_-]{43}$/.test(bearer),"surface_enrollment_auth_required",401);
  const signal=request.signal;
  const saved=await row(p.authorization_id,signal), tokenHash=await checked(signal,()=>sha256Hex(bearer.slice(7)));
  const matches=await checked(signal,()=>timingSafeEqualString(saved?.token_hash??"0".repeat(64),tokenHash));
  need(saved&&matches,"surface_enrollment_auth_required",401);
  const b=await checked(signal,()=>bindings(p.consent,e));
  need(saved.nonce_hash===b.nonce&&saved.action_key===b.action&&saved.consent_digest===b.consent&&saved.request_hash===b.request&&
   saved.key_thumbprint===b.key&&saved.scope_digest===b.scope&&saved.delegation_id===e.delegation_id&&saved.enrollment_operation_id===e.operation_id,
   "surface_enrollment_scope_mismatch",403);
  const key=await checked(signal,()=>publicKey(e.public_key));
  need(await checked(signal,()=>crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,bytes(envelope.signature,64),redemptionBytes(p))),"surface_enrollment_auth_required",401);
  const clock=now();operationDeadline(e.operation_id,clock);
  need(!request.signal.aborted,"surface_operation_cancelled",409);
  need(saved.state==="available"&&saved.revoked_at===null&&saved.expires_at>clock,"surface_enrollment_unavailable",409);
  const claim=crypto.randomUUID();
  const owns=`EXISTS(SELECT 1 FROM surface_enrollment_authorizations WHERE id=? AND claim_id=? AND state='consumed' AND outcome='pending')`;
  await commit(signal,()=>[
   db.prepare(`UPDATE surface_enrollment_authorizations SET state='consumed',outcome='pending',claim_id=?,consumed_at=?
    WHERE id=? AND token_hash=? AND request_hash=? AND consent_digest=? AND state='available' AND revoked_at IS NULL AND expires_at>? AND expires_at>${SQL_NOW}`)
    .bind(claim,clock,saved.id,tokenHash,b.request,b.consent,clock),
   db.prepare(`INSERT OR IGNORE INTO surface_push_operator_operations(operation_id,request_hash,delegation_id,kind,claim_id,outcome)
    SELECT ?,?,?,'enrol',?,'pending' WHERE ${owns}`).bind(e.operation_id,b.request,e.delegation_id,claim,saved.id,claim),
   db.prepare(`INSERT OR IGNORE INTO surface_push_delegations
    (id,revision,enrol_operation_id,approval_reference,install_id,device_binding,owner_binding,grant_binding,source_binding,binding_id,public_key_json,key_thumbprint,policy_json,scope_digest,expires_at,created_at,revoked_at)
    SELECT ?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL WHERE ${owns} AND
    EXISTS(SELECT 1 FROM surface_push_operator_operations WHERE operation_id=? AND request_hash=? AND claim_id=? AND outcome='pending')`)
    .bind(e.delegation_id,e.operation_id,e.approval_reference,e.install_id,e.device_binding,e.owner_binding,e.grant_binding,e.source_binding,e.binding_id,canonical(e.public_key),b.key,canonical(e.policy),b.scope,e.policy.original_grant_expires_at_ms,clock,saved.id,claim,e.operation_id,b.request,claim),
   db.prepare(`UPDATE surface_push_operator_operations SET outcome=CASE WHEN EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND enrol_operation_id=? AND scope_digest=?) THEN 'enrolled' ELSE 'conflict' END WHERE operation_id=? AND claim_id=?`)
    .bind(e.delegation_id,e.operation_id,b.scope,e.operation_id,claim),
   db.prepare(`UPDATE surface_enrollment_authorizations SET outcome=CASE WHEN EXISTS(SELECT 1 FROM surface_push_operator_operations WHERE operation_id=? AND request_hash=? AND claim_id=? AND outcome='enrolled') THEN 'enrolled' ELSE 'conflict' END WHERE id=? AND claim_id=? AND outcome='pending'`)
    .bind(e.operation_id,b.request,claim,saved.id,claim),
  ]);
  const final=await row(saved.id,signal);
  need(final?.claim_id===claim&&final.state==="consumed"&&final.outcome==="enrolled"&&final.revoked_at===null&&final.expires_at>now(),"surface_enrollment_unavailable",409);
  const live=await checked(signal,()=>db.prepare("SELECT 1 FROM surface_push_delegations WHERE id=? AND enrol_operation_id=? AND scope_digest=? AND revoked_at IS NULL AND expires_at>?").bind(e.delegation_id,e.operation_id,b.scope,now()).first());
  need(live&&final.expires_at>now(),"surface_enrollment_unavailable",409);
  guard(signal);return reply({contract_version:1,success:true,authorization_id:saved.id,enrollment_operation_id:e.operation_id,
   request_hash:b.request,consent_digest:b.consent,key_thumbprint:b.key,scope_digest:b.scope,
   expires_at_ms:e.policy.original_grant_expires_at_ms,state:"enrolled",replayed:false});
 }
 async function revoke(value:unknown,signal:AbortSignal) {
  closed(value,["contract_version","purpose","action","operation_id","authorization_id"]);
  need(value.contract_version===1&&value.purpose==="surface_enrollment"&&value.action==="revoke");id(value.authorization_id);
  need(typeof value.operation_id==="string");operationDeadline(value.operation_id,now());
  const hash=await checked(signal,()=>sha256Hex(canonical([ENROLLMENT_DOMAIN,"operator/revoke",value]))),claim=crypto.randomUUID(),clock=now();operationDeadline(value.operation_id,clock);
  need(!signal.aborted,"surface_operation_cancelled",409);
  await commit(signal,()=>[
   db.prepare("INSERT OR IGNORE INTO surface_enrollment_operator_operations VALUES(?,?,?,'revoke',?,'pending')").bind(value.operation_id,hash,value.authorization_id,claim),
   db.prepare(`UPDATE surface_enrollment_authorizations SET state='revoked',revoked_at=COALESCE(revoked_at,?) WHERE id=? AND EXISTS(SELECT 1 FROM surface_enrollment_operator_operations WHERE operation_id=? AND request_hash=? AND kind='revoke')`)
    .bind(clock,value.authorization_id,value.operation_id,hash),
   db.prepare("UPDATE surface_enrollment_operator_operations SET outcome='revoked' WHERE operation_id=? AND request_hash=? AND kind='revoke'").bind(value.operation_id,hash),
  ]);
  const op=await checked(signal,()=>db.prepare("SELECT request_hash,outcome FROM surface_enrollment_operator_operations WHERE operation_id=?").bind(value.operation_id).first<{request_hash:string;outcome:string}>());
  need(op?.request_hash===hash&&op.outcome==="revoked","surface_operation_conflict",409);
  guard(signal);return reply({contract_version:1,success:true,authorization_id:value.authorization_id,operation_id:value.operation_id,state:"revoked",scope:"enrollment_authorization_only"});
 }
 return async (request:Request)=>{
  try {
   const url=new URL(request.url),path=url.pathname.slice(ENROLLMENT_PREFIX.length);
   need(url.origin==="https://api.djconnect.dev"&&url.pathname.startsWith(ENROLLMENT_PREFIX)&&request.method==="POST"&&!url.search&&!url.hash,"surface_route_not_found",404);
   need(!request.headers.has("origin")&&!request.headers.has("cookie"),"surface_server_transport_required",403);
   need(["operator/authorize","operator/revoke","redeem"].includes(path),"surface_route_not_found",404);
   const signal=request.signal;guard(signal);
   const body=await checked(signal,()=>readBody(request));
   need(!request.signal.aborted,"surface_operation_cancelled",409);
   if(path.startsWith("operator/")) {
    await checked(signal,()=>requireAdminAuth(new Request(request.url,{method:"POST",headers:request.headers,body:body.raw}),authEnv));
    const response=path==="operator/authorize"?await authorizeOnce(body.value,signal):await revoke(body.value,signal);
    guard(signal);return response;
   }
   const response=await redeemOnce(body.value,request);guard(signal);return response;
  } catch(error) {
   if(error instanceof SurfaceError||error instanceof HttpError)return reply({contract_version:1,success:false,error:error.code},error.status);
   return reply({contract_version:1,success:false,error:"surface_enrollment_unavailable"},503);
  }
 };
}
