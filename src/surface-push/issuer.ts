/** Internal source only. No public-root import, automatic provisioning or provider traffic. */
import { requireAdminAuth } from "../auth";
import { base64Url, sha256Hex } from "../crypto";
import { HttpError } from "../http";
import type { AppEnv } from "../types";
import { canonical, need, SurfaceError } from "./wire";
import { bytes, closed, enrolment, id, ISSUER_PREFIX, ISSUER_VERSION, operationDeadline, publicKey, readBody, signingBytes, statement, thumbprint, type Enrolment, type Policy, type PurposeAction, type Statement } from "./issuer-wire";

interface Delegation {
 id: string; revision: number; install_id: string; device_binding: string; owner_binding: string;
 grant_binding: string; source_binding: string; binding_id: string;
 public_key_json: string; key_thumbprint: string; policy_json: string; scope_digest: string;
 expires_at: number; revoked_at: number | null;
}
interface IssuerOperation {
 request_hash: string; claim_id: string; outcome: string; challenge_id: string | null;
 expires_at: number; capability_id: string | null;
}
export interface IssuerOptions { env: AppEnv; now?: () => number; admittedProfiles?: readonly string[] }
function response(body: unknown, status = 200): Response {
 return new Response(JSON.stringify(body), { status, headers: { "content-type":"application/json; charset=utf-8", "cache-control":"no-store", "referrer-policy":"no-referrer", "x-content-type-options":"nosniff" } });
}
export function createSurfaceIssuer(options: IssuerOptions): (request: Request) => Promise<Response> {
 const db = options.env.DB; let highWater = 0;
 const now = () => { const value = (options.now ?? Date.now)(); need(Number.isSafeInteger(value) && value >= highWater && value >= 0, "surface_clock_unqualified", 503); highWater = value; return value; };
 const delegation = (name: string) => db.prepare("SELECT * FROM surface_push_delegations WHERE id=?").bind(name).first<Delegation>();
 const operation = (name: string, op: string, kind: string) => db.prepare("SELECT * FROM surface_push_issuer_operations WHERE delegation_id=? AND operation_id=? AND kind=?").bind(name,op,kind).first<IssuerOperation>();
 const active = (row: Delegation, clock: number) => need(row.revoked_at === null && row.expires_at > clock, "surface_delegation_unavailable", 403);
 async function signed(value: unknown, action: PurposeAction, path: string): Promise<{ input: Statement; row: Delegation; hash: string }> {
  const envelope = statement(value,action), input = envelope.payload;
  const row = await delegation(input.delegation_id);
  need(row && row.revision === input.delegation_revision && row.key_thumbprint === input.key_thumbprint, "surface_purpose_auth_required", 401);
  const key = await publicKey(JSON.parse(row.public_key_json) as Enrolment["public_key"]);
  need(await crypto.subtle.verify({ name:"ECDSA",hash:"SHA-256" }, key, bytes(envelope.signature,64), signingBytes(path,input)), "surface_purpose_auth_required", 401);
  if (action !== "status") operationDeadline(input.operation_id,now());
  if (action === "issue" || action === "challenge") active(row,now());
  return { input,row,hash:await sha256Hex(canonical([ISSUER_VERSION,path,input])) };
 }
 async function enrol(value: unknown): Promise<Response> {
  const input = enrolment(value,now(),options.admittedProfiles ?? []);
  await publicKey(input.public_key);
  const keyHash = await thumbprint(input.public_key), policy = canonical(input.policy);
  const scope = await sha256Hex(canonical([ISSUER_VERSION,"delegation",input.delegation_id,1,input.install_id,input.device_binding,input.owner_binding,input.grant_binding,input.source_binding,input.binding_id,keyHash,input.policy]));
  const hash = await sha256Hex(canonical([ISSUER_VERSION,"operator/enrol",input])), claim = crypto.randomUUID();
  operationDeadline(input.operation_id,now());
  await db.batch([
   db.prepare("INSERT OR IGNORE INTO surface_push_operator_operations(operation_id,request_hash,delegation_id,kind,claim_id,outcome) VALUES(?,?,?,'enrol',?,'pending')").bind(input.operation_id,hash,input.delegation_id,claim),
   db.prepare(`INSERT OR IGNORE INTO surface_push_delegations
    (id,revision,enrol_operation_id,approval_reference,install_id,device_binding,owner_binding,grant_binding,source_binding,binding_id,public_key_json,key_thumbprint,policy_json,scope_digest,expires_at,created_at,revoked_at)
    SELECT ?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL WHERE EXISTS(SELECT 1 FROM surface_push_operator_operations WHERE operation_id=? AND request_hash=? AND claim_id=? AND outcome='pending')`)
    .bind(input.delegation_id,input.operation_id,input.approval_reference,input.install_id,input.device_binding,input.owner_binding,input.grant_binding,input.source_binding,input.binding_id,canonical(input.public_key),keyHash,policy,scope,input.policy.original_grant_expires_at_ms,now(),input.operation_id,hash,claim),
   db.prepare(`UPDATE surface_push_operator_operations SET outcome=CASE WHEN EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND enrol_operation_id=? AND scope_digest=?) THEN 'enrolled' ELSE 'conflict' END WHERE operation_id=? AND claim_id=?`)
    .bind(input.delegation_id,input.operation_id,scope,input.operation_id,claim),
  ]);
  const op = await db.prepare("SELECT * FROM surface_push_operator_operations WHERE operation_id=?").bind(input.operation_id).first<{ request_hash:string; outcome:string; claim_id:string }>();
  need(op?.request_hash === hash && op.outcome === "enrolled", "surface_operation_conflict",409);
  const row = await delegation(input.delegation_id); need(row && row.scope_digest === scope,"surface_operation_conflict",409);
  const live = row.revoked_at === null && row.expires_at > now();
  return response({ contract_version:1,success:live,delegation_id:row.id,delegation_revision:row.revision,key_thumbprint:keyHash,scope_digest:scope,expires_at_ms:row.expires_at,state:live?"enrolled":"withdrawn",replayed:op.claim_id !== claim });
 }
 async function challenge(input: Statement, row: Delegation, hash: string): Promise<Response> {
  const priorIssue=await db.prepare("SELECT operation_id FROM surface_push_issuer_operations WHERE delegation_id=? AND kind='issue' AND outcome='issued'").bind(row.id).first<{operation_id:string}>();
  need(!priorIssue || priorIssue.operation_id===input.operation_id,"surface_delegation_already_issued",409);
  const policy = JSON.parse(row.policy_json) as Policy, claim = crypto.randomUUID(), challengeId = crypto.randomUUID();
  const nonce = base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer), nonceHash = await sha256Hex(nonce);
  const clock = now(), deadline = Math.min(clock+120000,operationDeadline(input.operation_id,clock),row.expires_at);
  await db.prepare(`INSERT OR IGNORE INTO surface_push_issuer_operations
   (delegation_id,operation_id,kind,request_hash,claim_id,outcome,challenge_id,nonce_hash,scope_digest,expires_at,capability_id,accepted_at)
   SELECT ?,?,'challenge',?,?,'challenge_open',?,?,?,?,NULL,? WHERE
   EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND revision=? AND scope_digest=? AND revoked_at IS NULL AND expires_at>?) AND
   (SELECT COUNT(*) FROM surface_push_issuer_operations WHERE delegation_id=? AND kind='challenge')<?`)
   .bind(row.id,input.operation_id,hash,claim,challengeId,nonceHash,row.scope_digest,deadline,clock,row.id,row.revision,row.scope_digest,clock,row.id,policy.max_challenges).run();
  const op = await operation(row.id,input.operation_id,"challenge");
  need(op,"surface_capacity_exhausted",429); need(op.request_hash === hash,"surface_operation_conflict",409);
  const current = await delegation(row.id); need(current,"surface_delegation_unavailable",403); active(current,now());
  const owns = op.claim_id === claim && op.outcome === "challenge_open" && op.expires_at > now();
  return response({ contract_version:1,success:owns,operation_id:input.operation_id,delegation_id:row.id,delegation_revision:row.revision,key_thumbprint:row.key_thumbprint,scope_digest:row.scope_digest,challenge_id:op.challenge_id,expires_at_ms:op.expires_at,state:owns?"challenge":"unknown",replayed:!owns,...(owns?{nonce}:{}) },owns?200:202);
 }
 async function issue(input: Statement, row: Delegation, hash: string): Promise<Response> {
  need(input.scope_digest === row.scope_digest,"surface_scope_mismatch",403);
  const old = await operation(row.id,input.operation_id,"issue");
  if (old) { need(old.request_hash === hash,"surface_operation_conflict",409); return status(input,row,true); }
  const nonceHash = await sha256Hex(input.nonce!), policy = JSON.parse(row.policy_json) as Policy;
  const claim = crypto.randomUUID(), capId = crypto.randomUUID();
  const token = "djcs_" + base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer), tokenHash = await sha256Hex(token);
  const clock = now(); operationDeadline(input.operation_id,clock);
  const exactChallenge = `EXISTS(SELECT 1 FROM surface_push_issuer_operations WHERE delegation_id=? AND operation_id=? AND kind='challenge' AND outcome='challenge_open' AND challenge_id=? AND nonce_hash=? AND scope_digest=? AND expires_at>?)`;
  const live = `EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND revision=? AND scope_digest=? AND revoked_at IS NULL AND expires_at>?)`;
  const challengeArgs = [row.id,input.operation_id,input.challenge_id,nonceHash,row.scope_digest,clock];
  await db.batch([
   db.prepare(`INSERT OR IGNORE INTO surface_push_issuer_operations
    (delegation_id,operation_id,kind,request_hash,claim_id,outcome,scope_digest,expires_at,capability_id,accepted_at)
   SELECT ?,?,'issue',?,?,'pending',?,?,?,? WHERE ${exactChallenge} AND ${live} AND
   NOT EXISTS(SELECT 1 FROM surface_push_issuer_operations WHERE delegation_id=? AND kind='issue' AND outcome='issued')`)
    .bind(row.id,input.operation_id,hash,claim,row.scope_digest,row.expires_at,capId,clock,...challengeArgs,row.id,row.revision,row.scope_digest,clock,row.id),
   db.prepare(`INSERT OR IGNORE INTO surface_push_capabilities
    (id,token_hash,install_id,device_binding,owner_binding,parent_bundle,extension_bundle,widget_kind,attributes_type,activity_profile,external_content_allowed,platform,environment,role,expires_at,revoked_at,max_operations,max_events,delegation_id,delegation_revision,binding_id,grant_binding,source_binding,scope_digest)
    SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,? WHERE
    EXISTS(SELECT 1 FROM surface_push_issuer_operations WHERE delegation_id=? AND operation_id=? AND kind='issue' AND claim_id=? AND outcome='pending') AND ${exactChallenge} AND ${live}`)
    .bind(capId,tokenHash,row.install_id,row.device_binding,row.owner_binding,policy.target.app_bundle_id,policy.target.extension_bundle_id??"",policy.target.widget_kind??"",policy.target.attributes_type??"",policy.activity_profile??"",policy.external_content_allowed?1:0,policy.platform,policy.apns_environment,policy.token_role,row.expires_at,policy.max_operations,policy.max_events,row.id,row.revision,row.binding_id,row.grant_binding,row.source_binding,row.scope_digest,row.id,input.operation_id,claim,...challengeArgs,row.id,row.revision,row.scope_digest,clock),
   db.prepare(`UPDATE surface_push_issuer_operations SET outcome=CASE WHEN EXISTS(SELECT 1 FROM surface_push_capabilities WHERE id=? AND token_hash=?) THEN 'issued' ELSE 'conflict' END WHERE delegation_id=? AND operation_id=? AND kind='issue' AND claim_id=?`)
    .bind(capId,tokenHash,row.id,input.operation_id,claim),
   db.prepare(`UPDATE surface_push_issuer_operations SET outcome='challenge_consumed' WHERE delegation_id=? AND operation_id=? AND kind='challenge' AND outcome='challenge_open' AND EXISTS(SELECT 1 FROM surface_push_issuer_operations i WHERE i.delegation_id=? AND i.operation_id=? AND i.kind='issue' AND i.claim_id=? AND i.outcome='issued')`)
    .bind(row.id,input.operation_id,row.id,input.operation_id,claim),
  ]);
  const op = await operation(row.id,input.operation_id,"issue"); need(op,"surface_challenge_unavailable",409);
  need(op.request_hash === hash && op.outcome === "issued","surface_operation_conflict",409);
  const usable = await db.prepare("SELECT 1 FROM surface_push_live_capabilities WHERE id=? AND expires_at>?").bind(op.capability_id,now()).first();
  const owns = op.claim_id === claim && !!usable;
  return response({ contract_version:1,success:owns,operation_id:input.operation_id,delegation_id:row.id,delegation_revision:row.revision,scope_digest:row.scope_digest,capability_id:op.capability_id,expires_at_ms:op.expires_at,state:usable?"issued":"withdrawn",replayed:op.claim_id!==claim,...(owns?{credential:token}:{}) },owns?200:202);
 }
 async function status(input: Statement, row: Delegation, replayed = false): Promise<Response> {
  const op = await operation(row.id,input.operation_id,"issue");
  const live = op?.capability_id ? await db.prepare("SELECT 1 FROM surface_push_live_capabilities WHERE id=? AND expires_at>?").bind(op.capability_id,now()).first() : null;
  return response({ contract_version:1,success:false,operation_id:input.operation_id,delegation_id:row.id,delegation_revision:row.revision,scope_digest:row.scope_digest,capability_id:op?.capability_id??null,expires_at_ms:op?.expires_at??row.expires_at,state:op?.outcome === "issued"?(live?"issued":"withdrawn"):"unknown",credential_state:"unavailable",replayed });
 }
 async function withdraw(input: Pick<Statement,"delegation_id"|"delegation_revision"|"operation_id">, row: Delegation, hash: string): Promise<Response> {
  const claim = crypto.randomUUID(), clock = now(); operationDeadline(input.operation_id,clock);
  await db.batch([
   db.prepare(`INSERT OR IGNORE INTO surface_push_issuer_operations(delegation_id,operation_id,kind,request_hash,claim_id,outcome,scope_digest,expires_at,accepted_at) VALUES(?,?,'withdraw',?,?,'pending',?,?,?)`)
    .bind(row.id,input.operation_id,hash,claim,row.scope_digest,row.expires_at,clock),
   db.prepare(`UPDATE surface_push_delegations SET revoked_at=COALESCE(revoked_at,?) WHERE id=? AND revision=? AND EXISTS(SELECT 1 FROM surface_push_issuer_operations WHERE delegation_id=? AND operation_id=? AND kind='withdraw' AND claim_id=? AND outcome='pending')`)
    .bind(clock,row.id,row.revision,row.id,input.operation_id,claim),
   db.prepare(`UPDATE surface_push_capabilities SET revoked_at=COALESCE(revoked_at,?) WHERE delegation_id=? AND EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND revision=? AND revoked_at IS NOT NULL)`)
    .bind(clock,row.id,row.id,row.revision),
   db.prepare(`UPDATE surface_push_targets SET state='revoked',ciphertext=NULL,nonce=NULL WHERE capability_id IN(SELECT id FROM surface_push_capabilities WHERE delegation_id=? AND revoked_at IS NOT NULL)`).bind(row.id),
   db.prepare("UPDATE surface_push_issuer_operations SET outcome='challenge_withdrawn' WHERE delegation_id=? AND kind='challenge' AND outcome='challenge_open' AND EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND revoked_at IS NOT NULL)").bind(row.id,row.id),
   db.prepare("UPDATE surface_push_issuer_operations SET outcome='withdrawn' WHERE delegation_id=? AND operation_id=? AND kind='withdraw' AND claim_id=? AND EXISTS(SELECT 1 FROM surface_push_delegations WHERE id=? AND revoked_at IS NOT NULL)").bind(row.id,input.operation_id,claim,row.id),
  ]);
  const op = await operation(row.id,input.operation_id,"withdraw"); need(op?.request_hash===hash && op.outcome==="withdrawn","surface_operation_conflict",409);
  return response({contract_version:1,success:true,delegation_id:row.id,delegation_revision:row.revision,operation_id:input.operation_id,state:"withdrawn",expires_at_ms:row.expires_at,replayed:op.claim_id!==claim});
 }
 return async request => {
  try {
   const url = new URL(request.url), route = url.pathname.slice(ISSUER_PREFIX.length);
   need(url.pathname.startsWith(ISSUER_PREFIX) && request.method==="POST" && !url.search && !url.hash,"surface_route_not_found",404);
   need(!request.headers.has("origin") && !request.headers.has("cookie"),"surface_server_transport_required",403);
   need(["operator/enrol","operator/withdraw","challenge","issue","status","withdraw"].includes(route),"surface_route_not_found",404);
   const body = await readBody(request);
   if (route.startsWith("operator/")) {
    await requireAdminAuth(new Request(request.url,{method:"POST",headers:request.headers,body:body.raw}),options.env);
    if (route==="operator/enrol") return await enrol(body.value);
    const v=body.value; closed(v,["contract_version","purpose","action","operation_id","delegation_id","delegation_revision"]);
    need(v.contract_version===1 && v.purpose==="surface_push" && v.action==="withdraw" && v.delegation_revision===1);
    id(v.delegation_id); need(typeof v.operation_id==="string");
    const row=await delegation(v.delegation_id); need(row,"surface_delegation_unavailable",404);
    operationDeadline(v.operation_id,now());
    const hash=await sha256Hex(canonical([ISSUER_VERSION,route,v])), claim=crypto.randomUUID();
    await db.prepare("INSERT OR IGNORE INTO surface_push_operator_operations(operation_id,request_hash,delegation_id,kind,claim_id,outcome) VALUES(?,?,?,'withdraw',?,'pending')").bind(v.operation_id,hash,row.id,claim).run();
    const operator=await db.prepare("SELECT request_hash FROM surface_push_operator_operations WHERE operation_id=?").bind(v.operation_id).first<{request_hash:string}>();
    need(operator?.request_hash===hash,"surface_operation_conflict",409);
    const result=await withdraw(v as unknown as Statement,row,hash);
    await db.prepare("UPDATE surface_push_operator_operations SET outcome='withdrawn' WHERE operation_id=? AND request_hash=?").bind(v.operation_id,hash).run();
    return result;
   }
   need(!request.headers.has("authorization"),"surface_purpose_auth_required",401);
   const action=route as PurposeAction, verified=await signed(body.value,action,url.pathname);
   if (action==="challenge") return await challenge(verified.input,verified.row,verified.hash);
   if (action==="issue") return await issue(verified.input,verified.row,verified.hash);
   if (action==="withdraw") return await withdraw(verified.input,verified.row,verified.hash);
   return await status(verified.input,verified.row);
  } catch (error) {
   if (error instanceof SurfaceError || error instanceof HttpError) return response({contract_version:1,success:false,error:error.code},error.status);
   return response({contract_version:1,success:false,error:"surface_issuer_unavailable"},503);
  }
 };
}
