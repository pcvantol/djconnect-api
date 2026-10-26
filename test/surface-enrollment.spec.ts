import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import baseMigration from "../migrations/0009_surface_push.sql?raw";
import issuerMigration from "../migrations/0010_surface_delegations.sql?raw";
import enrollmentMigration from "../migrations/0011_surface_enrollment_authorizations.sql?raw";
import publicVector from "../qualification/surface-push/enrollment-public-vectors-v1.json";
import { base64Url } from "../src/crypto";
import type { AppEnv } from "../src/types";
import { canonical } from "../src/surface-push/wire";
import { createSurfaceEnrollment } from "../src/surface-push/enrollment";
import { createSurfaceService } from "../src/surface-push/composition";
import { authorize, redeem, bindings, ENROLLMENT_PREFIX, redemptionBytes, type Authorization, type Redemption } from "../src/surface-push/enrollment-wire";
import { bytes, publicKey } from "../src/surface-push/issuer-wire";
import { dispatchSurfaceRequest } from "../src/surface-push/dispatch";

// Actual disposable SQLite/software signatures only; no operator/key/native admission.
const NOW=Date.now(), END=NOW+900000, OPERATOR="synthetic-enrollment-operator";
let seq=0,clock=NOW,key:CryptoKey,otherKey:CryptoKey,jwk:Authorization["enrollment"]["public_key"];
function op(time=NOW) {return time.toString(16).padStart(12,"0").replace(/^(.{8})(.{4})$/,"$1-$2")+"-7000-8000-"+(++seq).toString(16).padStart(12,"0");}
function input():Authorization {return {contract_version:1,purpose:"surface_enrollment",action:"authorize",operation_id:op(),authorization_id:"synthetic-ticket",
 consent:{nonce:base64Url(new Uint8Array(32).fill(1).buffer),action_id:"synthetic-action",generation_id:"synthetic-generation",plan_digest:"a".repeat(64),expires_at_ms:END},
 enrollment:{contract_version:1,purpose:"surface_push",action:"enrol",operation_id:op(),delegation_id:"synthetic-delegation",expected_revision:0,
 approval_reference:"synthetic-only-not-human-consent",install_id:"synthetic-install",device_binding:"1".repeat(64),owner_binding:"2".repeat(64),grant_binding:"3".repeat(64),source_binding:"4".repeat(64),binding_id:"5".repeat(64),public_key:jwk,
 policy:{token_role:"widget",platform:"ios",apns_environment:"sandbox",target:{app_bundle_id:"dev.synthetic.ios",extension_bundle_id:"dev.synthetic.ios.widget",widget_kind:"synthetic"},activity_profile:null,external_content_allowed:false,original_grant_expires_at_ms:END,max_operations:4,max_events:2,max_challenges:1}}};}
function handler(){return createSurfaceEnrollment({env:{DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock});}
async function call(h:ReturnType<typeof handler>,path:string,body:unknown,token?:string,signal?:AbortSignal){return h(new Request("https://api.djconnect.dev"+ENROLLMENT_PREFIX+path,{method:"POST",headers:{"content-type":"application/json",...(token?{authorization:"Bearer "+token}:{})},body:typeof body==="string"?body:canonical(body),signal}));}
async function authorized(h=handler(),value=input()) {const response=await call(h,"operator/authorize",value,OPERATOR);const receipt=await response.json() as any;expect(response.status,JSON.stringify(receipt)).toBe(200);expect(receipt.credential).toMatch(/^djce_[A-Za-z0-9_-]{43}$/);return {h,value,receipt};}
function payload(a:Authorization):Redemption{return {contract_version:1,purpose:"surface_enrollment",action:"redeem",authorization_id:a.authorization_id,consent:a.consent,enrollment:a.enrollment};}
async function proof(p:Redemption,signer=key){return {payload:p,signature:base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},signer,redemptionBytes(p)))};}
const count=(table:string)=>env.DB.prepare("SELECT COUNT(*) AS n FROM "+table).first("n");
function revoke(a:Authorization){return {contract_version:1,purpose:"surface_enrollment",action:"revoke",operation_id:op(clock),authorization_id:a.authorization_id};}

describe("single use enrollment with actual D1 and synthetic authority",()=>{
 beforeAll(async()=>{
  for(const sql of (baseMigration+"\n"+issuerMigration+"\n"+enrollmentMigration).split(";").filter(s=>s.replace(/--[^\n]*/g,"").trim()))await env.DB.prepare(sql).run();
  const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair;
  key=pair.privateKey;const j=(await crypto.subtle.exportKey("jwk",pair.publicKey)) as JsonWebKey;jwk={kty:"EC",crv:"P-256",x:j.x!,y:j.y!};
  otherKey=(await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair).privateKey;
 });
 beforeEach(async()=>{seq=0;clock=NOW;vi.restoreAllMocks();for(const t of ["surface_enrollment_authorizations","surface_enrollment_operator_operations","surface_push_operator_operations","surface_push_delegations"])await env.DB.prepare("DELETE FROM "+t).run();});
 it("actual API codecs and workerd ES256 verify independent expired public vectors",async()=>{
  const a=authorize(publicVector.authorization_request,publicVector.original_reference_wall_ms);
  const p=redeem(publicVector.redemption_request,publicVector.original_reference_wall_ms);
  expect(await bindings(a.consent,a.enrollment)).toEqual(publicVector.expected_bindings);
  expect(new TextDecoder().decode(redemptionBytes(p.payload))).toBe(publicVector.redemption_signing_bytes_utf8);
  expect(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},await publicKey(a.enrollment.public_key),bytes(p.signature,64),redemptionBytes(p.payload))).toBe(true);
 });
 it("returns credential once, stores only its hash and performs no enrollment at authorization",async()=>{
  const x=await authorized();expect(await count("surface_push_delegations")).toBe(0);
  const rows=JSON.stringify(await env.DB.prepare("SELECT * FROM surface_enrollment_authorizations").all());expect(rows).not.toContain(x.receipt.credential);expect(rows).not.toContain(x.value.consent.nonce);
  expect(await (await call(x.h,"operator/authorize",x.value,OPERATOR)).json()).toMatchObject({success:false,credential_state:"unavailable",replayed:true});
  expect(await count("surface_enrollment_authorizations")).toBe(1);
 });
 it("enrolls the bound original scope once and refuses replay",async()=>{
  const x=await authorized(),p=await proof(payload(x.value));const first=await call(x.h,"redeem",p,x.receipt.credential);
  const b=await bindings(x.value.consent,x.value.enrollment);
  expect(await first.json()).toEqual({contract_version:1,success:true,authorization_id:x.value.authorization_id,enrollment_operation_id:x.value.enrollment.operation_id,request_hash:b.request,consent_digest:b.consent,key_thumbprint:b.key,scope_digest:b.scope,expires_at_ms:END,state:"enrolled",replayed:false});
  expect((await call(handler(),"redeem",p,x.receipt.credential)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(1);
 });
 it("concurrent redemption has exactly one winning reply and delegation",async()=>{
  const x=await authorized(),p=await proof(payload(x.value));const results=await Promise.all([call(x.h,"redeem",p,x.receipt.credential),call(handler(),"redeem",p,x.receipt.credential)]);
  expect(results.map(r=>r.status).sort()).toEqual([200,409]);expect(await count("surface_push_delegations")).toBe(1);
 });
 it("concurrent authorization discloses exactly one raw credential",async()=>{
  const h=handler(),a=input();const results=await Promise.all([call(h,"operator/authorize",a,OPERATOR),call(handler(),"operator/authorize",a,OPERATOR)]);
  expect(results.map(r=>r.status).sort()).toEqual([200,202]);
  const bodies=await Promise.all(results.map(r=>r.json() as Promise<any>));expect(bodies.filter(b=>typeof b.credential==="string")).toHaveLength(1);
  expect(await count("surface_enrollment_authorizations")).toBe(1);
 });
 it.each([undefined,"djci_synthetic","djcs_synthetic","wrong"])("rejects nonoperator authorization %s",async token=>{
  expect([401,403]).toContain((await call(handler(),"operator/authorize",input(),token)).status);expect(await count("surface_enrollment_authorizations")).toBe(0);
 });
 it.each([OPERATOR,"djcs_synthetic","djci_synthetic","djce_"+"A".repeat(43)])("cannot redeem with another credential class/value %#",async token=>{
  const x=await authorized();expect((await call(x.h,"redeem",await proof(payload(x.value)),token)).status).toBe(401);expect(await count("surface_push_delegations")).toBe(0);
 });
 it.each(["nonce","action_id","generation_id","plan_digest","expires_at_ms"] as const)("binds original consent %s",async field=>{
  const x=await authorized(),p=payload(x.value);
  p.consent={...p.consent,[field]:field==="expires_at_ms"?END-1:field==="nonce"?"A".repeat(43):field==="plan_digest"?"b".repeat(64):"changed"};
  expect([400,403]).toContain((await call(x.h,"redeem",await proof(p),x.receipt.credential)).status);expect(await count("surface_push_delegations")).toBe(0);
 });
 it.each(["owner_binding","grant_binding","source_binding","binding_id","device_binding"] as const)("binds exact tuple %s",async field=>{
  const x=await authorized(),p=payload(x.value);p.enrollment={...p.enrollment,[field]:"f".repeat(64)};
  expect((await call(x.h,"redeem",await proof(p),x.receipt.credential)).status).toBe(403);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("requires real proof of possession, not only a stolen ticket",async()=>{
  const x=await authorized();expect((await call(x.h,"redeem",await proof(payload(x.value),otherKey),x.receipt.credential)).status).toBe(401);
  expect(await count("surface_push_delegations")).toBe(0);
 });
 it("rejects a valid signature in another domain",async()=>{
  const x=await authorized(),p=payload(x.value);const signature=base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,new TextEncoder().encode(canonical(["wrong-domain",p]))));
  expect((await call(x.h,"redeem",{payload:p,signature},x.receipt.credential)).status).toBe(401);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("expiry during real signature verification prevents atomic mutation",async()=>{
  const x=await authorized(),p=await proof(payload(x.value)),original=crypto.subtle.verify.bind(crypto.subtle);
  vi.spyOn(crypto.subtle,"verify").mockImplementation(async(...args:Parameters<typeof crypto.subtle.verify>)=>{
   const result=await original(...args);clock=NOW+300000;return result;
  });
  expect((await call(x.h,"redeem",p,x.receipt.credential)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
  expect(await env.DB.prepare("SELECT state FROM surface_enrollment_authorizations").first("state")).toBe("available");
 });
 it("cancellation during signature verification prevents mutation",async()=>{
  const x=await authorized(),p=await proof(payload(x.value)),s=new AbortController(),original=crypto.subtle.verify.bind(crypto.subtle);
  vi.spyOn(crypto.subtle,"verify").mockImplementation(async(...args:Parameters<typeof crypto.subtle.verify>)=>{const result=await original(...args);s.abort();return result;});
  expect((await call(x.h,"redeem",p,x.receipt.credential,s.signal)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("rejects altered policy or new enrollment operation",async()=>{
  const x=await authorized();for(const e of [{...x.value.enrollment,operation_id:op()},{...x.value.enrollment,policy:{...x.value.enrollment.policy,max_operations:3}}]){
   expect((await call(x.h,"redeem",await proof({...payload(x.value),enrollment:e}),x.receipt.credential)).status).toBe(403);
  }expect(await count("surface_push_delegations")).toBe(0);
 });
 it("keeps nonce and original action unique across new authorization IDs/operations",async()=>{
  const x=await authorized();const next={...x.value,authorization_id:"replacement",operation_id:op(),enrollment:{...x.value.enrollment,delegation_id:"replacement",operation_id:op()}};
  expect((await call(x.h,"operator/authorize",next,OPERATOR)).status).toBe(409);
  next.consent={...next.consent,nonce:"A".repeat(43)};
  expect((await call(x.h,"operator/authorize",next,OPERATOR)).status).toBe(409);expect(await count("surface_enrollment_authorizations")).toBe(1);
 });
 it("revokes before redemption and preserves tombstone against delayed authorization",async()=>{
  const h=handler(),a=input();expect((await call(h,"operator/revoke",revoke(a),OPERATOR)).status).toBe(200);
  expect((await call(h,"operator/authorize",a,OPERATOR)).status).toBe(409);
  const x=await authorized(handler(),{...input(),authorization_id:"other",consent:{...a.consent,nonce:"A".repeat(43),action_id:"other"}});
  expect((await call(x.h,"operator/revoke",revoke(x.value),OPERATOR)).status).toBe(200);
  expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("operator ticket revoke works after expiry but has no delegation-withdrawal power",async()=>{
  const x=await authorized();expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(200);
  clock=END+1;const result=await call(x.h,"operator/revoke",revoke(x.value),OPERATOR);
  expect(await result.json()).toMatchObject({success:true,scope:"enrollment_authorization_only"});
  expect(await env.DB.prepare("SELECT revoked_at FROM surface_push_delegations").first("revoked_at")).toBe(null);
 });
 it("rejects expired original operation without extending ticket or enrolling",async()=>{
  const x=await authorized();clock=NOW+300000;expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("SQL wall time refuses a transaction queued beyond original ticket expiry",async()=>{
  const x=await authorized();await env.DB.prepare("UPDATE surface_enrollment_authorizations SET expires_at=?").bind(Date.now()-1).run();
  expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("atomic rollback leaves ticket unconsumed and zero enrollment after an actual SQL failure",async()=>{
  const x=await authorized();await env.DB.prepare("CREATE TRIGGER synthetic_enrollment_failure BEFORE INSERT ON surface_push_delegations BEGIN SELECT RAISE(ABORT,'synthetic_failure'); END").run();
  try {
   expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(503);
   expect(await env.DB.prepare("SELECT state FROM surface_enrollment_authorizations").first("state")).toBe("available");
   expect(await count("surface_push_delegations")).toBe(0);expect(await count("surface_push_operator_operations")).toBe(0);
  } finally {await env.DB.prepare("DROP TRIGGER synthetic_enrollment_failure").run();}
  // No retry is performed; a caller cannot infer this internal rollback from an unknown reply.
 });
 it("changed authorize operation digest cannot overwrite or mint a new secret",async()=>{
  const x=await authorized();expect((await call(x.h,"operator/authorize",{...x.value,authorization_id:"other"},OPERATOR)).status).toBe(409);expect(await count("surface_enrollment_authorizations")).toBe(1);
 });
 it("an existing enrollment operator operation cannot be overwritten by redemption",async()=>{
  const x=await authorized();await env.DB.prepare("INSERT INTO surface_push_operator_operations VALUES(?,?,?,'withdraw',?,'withdrawn')").bind(x.value.enrollment.operation_id,"f".repeat(64),x.value.enrollment.delegation_id,"synthetic-other-claim").run();
  expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(409);
  expect(await count("surface_push_delegations")).toBe(0);expect(await env.DB.prepare("SELECT kind FROM surface_push_operator_operations").first("kind")).toBe("withdraw");
  expect(await env.DB.prepare("SELECT state,outcome FROM surface_enrollment_authorizations").first()).toEqual({state:"consumed",outcome:"conflict"});
 });
 it("enrollment has no provider request or push capability issuance",async()=>{
  const fetch=vi.spyOn(globalThis,"fetch").mockRejectedValue(new Error("provider must not be called"));
  const before=await count("surface_push_capabilities"),x=await authorized();expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(200);
  expect(fetch).not.toHaveBeenCalled();expect(await count("surface_push_capabilities")).toBe(before);
 });
 it("pre-aborted redemption cannot mutate",async()=>{
  const x=await authorized(),s=new AbortController();s.abort();expect((await call(x.h,"redeem",await proof(payload(x.value)),x.receipt.credential,s.signal)).status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
 });
 it.each(["operator/authorize","operator/revoke","redeem"])("public root stays503 for %s without inspecting credentials or body",async path=>{
  const raw=new Request("https://api.djconnect.dev"+ENROLLMENT_PREFIX+path,{method:"POST",body:"untrusted"});
  const response=await dispatchSurfaceRequest(raw,new Proxy({},{get(){throw Error("env must stay untouched");}}));
  expect(response?.status).toBe(503);
 });
 it("rejects private/extra keys, Activity rights, duplicate JSON and overlong grants",async()=>{
  const a=input();const cases=[{...a,enrollment:{...a.enrollment,public_key:{...jwk,d:"forbidden"}}},
   {...a,enrollment:{...a.enrollment,policy:{...a.enrollment.policy,token_role:"live_activity_update"}}},
   {...a,consent:{...a.consent,expires_at_ms:END+1}}, {...a,consent:{...a.consent,expires_at_ms:END-1}}];
  for(const value of cases)expect([400,403]).toContain((await call(handler(),"operator/authorize",value,OPERATOR)).status);
  expect((await call(handler(),"operator/authorize",'{"contract_version":1,"contract_version":1}',OPERATOR)).status).toBe(400);
  expect(await count("surface_enrollment_authorizations")).toBe(0);
 });

 // Causal controls use actual D1 and synthetic software authority only.
 for (const stage of ["admin-digest","public-key-import"] as const) for (const stop of ["retire","abort"] as const) {
  it(`original service ${stop} during ${stage} cannot reach mutation`,async()=>{
   let current=true,release!:()=>void,entered!:()=>void;
   const waiting=new Promise<void>(r=>release=r),started=new Promise<void>(r=>entered=r);
   const control=new AbortController(),options={env:{DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock,isCurrent:()=>current};
   const h=createSurfaceEnrollment(options);let captured=false;
   const pause=async()=>{if(!captured){captured=true;entered();await waiting;}};
   if(stage==="admin-digest") {
    const original=crypto.subtle.digest.bind(crypto.subtle);
    vi.spyOn(crypto.subtle,"digest").mockImplementation(async(...args)=>{const value=await original(...args);await pause();return value;});
   } else {
    const original=crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle,"importKey").mockImplementation(async(...args)=>{const value=await original(...args);await pause();return value;});
   }
   const value=input(),pending=call(h,"operator/authorize",value,OPERATOR,control.signal);
   await started;if(stop==="retire")current=false;else control.abort();release();
   const response=await pending;expect(response.status).toBe(stop==="retire"?503:409);
   expect(await response.json()).not.toHaveProperty("credential");
   expect(await count("surface_enrollment_authorizations")).toBe(0);
   expect(await count("surface_enrollment_operator_operations")).toBe(0);
   if(stop==="retire") {current=true;expect((await call(h,"operator/authorize",value,OPERATOR)).status).toBe(503);}
  });
 }
 for(const action of ["operator/authorize","redeem","operator/revoke"] as const) for(const stop of ["retire","abort"] as const) {
  it(`last no-await guard prevents ${action} batch after ${stop} during statement binding`,async()=>{
   const seed=action==="operator/authorize"?null:await authorized();
   const value=seed?.value??input(),body=action==="redeem"?await proof(payload(value)):action==="operator/revoke"?revoke(value):value;
   const control=new AbortController();let current=true,batches=0,changed=false;
   const db=new Proxy(env.DB,{get(target,name){
    if(name==="prepare")return (...args:Parameters<D1Database["prepare"]>)=>{
     if(!changed&&args[0].startsWith(action==="redeem"?"UPDATE surface_enrollment_authorizations SET state='consumed'":"INSERT OR IGNORE INTO surface_enrollment_operator_operations")) {
      changed=true;if(stop==="retire")current=false;else control.abort();
     }
     return target.prepare(...args);
    };
    if(name==="batch")return (...args:Parameters<D1Database["batch"]>)=>{batches++;return target.batch(...args);};
    const member=Reflect.get(target,name);return typeof member==="function"?member.bind(target):member;
   }});
   const h=createSurfaceEnrollment({env:{DB:db,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock,isCurrent:()=>current});
   const response=await call(h,action,body,action==="redeem"?seed!.receipt.credential:OPERATOR,control.signal);
   expect(changed).toBe(true);expect(response.status).toBe(stop==="retire"?503:409);expect(batches).toBe(0);
   expect(await count("surface_push_delegations")).toBe(0);
   expect(await count("surface_enrollment_operator_operations")).toBe(seed?1:0);
   if(seed)expect(await env.DB.prepare("SELECT state FROM surface_enrollment_authorizations").first("state")).toBe("available");
  });
 }
 for(const action of ["operator/authorize","redeem","operator/revoke"] as const) for(const stop of ["retire","abort"] as const) {
  it(`submitted ${action} commit remains real after ${stop}; no positive result or rollback fiction`,async()=>{
   const seed=action==="operator/authorize"?null:await authorized();
   const value=seed?.value??input(),body=action==="redeem"?await proof(payload(value)):action==="operator/revoke"?revoke(value):value;
   const control=new AbortController();let current=true,batches=0;
   const db=new Proxy(env.DB,{get(target,name){
    if(name==="batch")return async(...args:Parameters<D1Database["batch"]>)=>{
     batches++;const result=await target.batch(...args);if(stop==="retire")current=false;else control.abort();return result;
    };
    const member=Reflect.get(target,name);return typeof member==="function"?member.bind(target):member;
   }});
   const h=createSurfaceEnrollment({env:{DB:db,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock,isCurrent:()=>current});
   const response=await call(h,action,body,action==="redeem"?seed!.receipt.credential:OPERATOR,control.signal);
   expect(response.status).toBe(stop==="retire"?503:409);expect(batches).toBe(1);
   expect(await response.json()).not.toHaveProperty("credential");
   expect(await env.DB.prepare("SELECT state FROM surface_enrollment_authorizations").first("state")).toBe(action==="redeem"?"consumed":action==="operator/revoke"?"revoked":"available");
   expect(await count("surface_push_delegations")).toBe(action==="redeem"?1:0);
  });
 }
 it("internal closed service routes enrollment without any provider key or provider call",async()=>{
  const transport=vi.fn(async()=>new Response("{}"));
  const config={DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv;
  const service=createSurfaceService({env:config,now:()=>clock,fetcher:transport});
  try {
   const h=(r:Request)=>service.handle(r),x=await authorized(h);
   expect((await call(h,"redeem",await proof(payload(x.value)),x.receipt.credential)).status).toBe(200);
   expect(await count("surface_push_delegations")).toBe(1);expect(transport).not.toHaveBeenCalled();
  } finally {service.close();}
 });
 it("observed outer service retirement cannot be reversed by a currentness ABA",async()=>{
  let current=true;const config={DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv;
  const service=createSurfaceService({env:config,now:()=>clock,isCurrent:()=>current});
  expect(service.matches(config)).toBe(true);current=false;expect(service.matches(config)).toBe(false);
  current=true;expect(service.matches(config)).toBe(false);
  await expect(call(r=>service.handle(r),"operator/authorize",input(),OPERATOR)).rejects.toMatchObject({code:"surface_service_unavailable"});
  expect(await count("surface_enrollment_authorizations")).toBe(0);service.close();
 });

 for(const change of ["db","secret","clock-callback","current-callback","clock-value"] as const) {
  it(`immutable ${change} cannot be replaced while public key import is suspended`,async()=>{
   let release!:()=>void,entered!:()=>void;const waiting=new Promise<void>(r=>release=r),started=new Promise<void>(r=>entered=r);
   const config={DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv;
   const originalClock=()=>clock,originalCurrent=()=>true,options={env:config,now:originalClock,isCurrent:originalCurrent};
   const h=createSurfaceEnrollment(options),original=crypto.subtle.importKey.bind(crypto.subtle);let paused=false;
   vi.spyOn(crypto.subtle,"importKey").mockImplementation(async(...args)=>{const result=await original(...args);if(!paused){paused=true;entered();await waiting;}return result;});
   const value=input(),pending=call(h,"operator/authorize",value,OPERATOR);await started;
   if(change==="db")config.DB={} as D1Database;
   if(change==="secret")config.DJCONNECT_RELAY_SECRET="synthetic-replacement-secret";
   if(change==="clock-callback")options.now=()=>clock;
   if(change==="current-callback")options.isCurrent=()=>true;
   if(change==="clock-value")clock=NOW-1;
   release();expect((await pending).status).toBe(503);expect(await count("surface_enrollment_authorizations")).toBe(0);
   config.DB=env.DB;config.DJCONNECT_RELAY_SECRET=OPERATOR;options.now=originalClock;options.isCurrent=originalCurrent;clock=NOW;
   expect((await call(h,"operator/authorize",value,OPERATOR)).status).toBe(503);
  });
 }
 for(const stop of ["retire","abort"] as const) {
  it(`pending original body ${stop} cannot enter admin or DB work`,async()=>{
   let deliver!:()=>void;const control=new AbortController();let current=true;
   const body=new ReadableStream<Uint8Array>({start(c){deliver=()=>{c.enqueue(new TextEncoder().encode(canonical(input())));c.close();};}});
   const h=createSurfaceEnrollment({env:{DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock,isCurrent:()=>current});
   const digest=vi.spyOn(crypto.subtle,"digest");
   const pending=h(new Request("https://api.djconnect.dev"+ENROLLMENT_PREFIX+"operator/authorize",{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+OPERATOR},body,signal:control.signal}));
   if(stop==="retire")current=false;else control.abort();deliver();
   expect((await pending).status).toBe(stop==="retire"?503:409);expect(digest).not.toHaveBeenCalled();
   expect(await count("surface_enrollment_operator_operations")).toBe(0);
  });
 }
 it("closed outer service during original enrollment import cannot submit a batch",async()=>{
  let release!:()=>void,entered!:()=>void;const waiting=new Promise<void>(r=>release=r),started=new Promise<void>(r=>entered=r);
  const original=crypto.subtle.importKey.bind(crypto.subtle);let paused=false;
  vi.spyOn(crypto.subtle,"importKey").mockImplementation(async(...args)=>{const result=await original(...args);if(!paused){paused=true;entered();await waiting;}return result;});
  const config={DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,service=createSurfaceService({env:config,now:()=>clock});
  const pending=call(r=>service.handle(r),"operator/authorize",input(),OPERATOR);await started;service.close();release();
  await expect(pending).rejects.toMatchObject({code:"surface_service_unavailable"});
  expect(await count("surface_enrollment_operator_operations")).toBe(0);expect(service.matches(config)).toBe(false);
 });
});
