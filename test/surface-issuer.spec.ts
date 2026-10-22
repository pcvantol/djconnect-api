import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import migration from "../migrations/0009_surface_push.sql?raw";
import vectors from "../qualification/surface-push/issuer-public-vectors.json";
import purposeMigration from "../migrations/0010_surface_delegations.sql?raw";
import { base64Url } from "../src/crypto";
import type { AppEnv } from "../src/types";
import { canonical } from "../src/surface-push/wire";
import { createSurfaceIssuer } from "../src/surface-push/issuer";
import { createSurfacePushHandler } from "../src/surface-push/handler";
import { ISSUER_PREFIX, signingBytes, thumbprint, type Enrolment, type Statement } from "../src/surface-push/issuer-wire";

const NOW = Math.floor(Date.now()/1000)*1000, END = NOW+3600000, OPERATOR = "example-purpose-operator-only", AES = btoa("0123456789abcdef0123456789abcdef");
let sequence=0, clock=NOW, key:CryptoKey, otherKey:CryptoKey, jwk:Enrolment["public_key"], keyHash:string;
function op(time=NOW) { return time.toString(16).padStart(12,"0").replace(/^(.{8})(.{4})$/,"$1-$2")+"-7000-8000-"+(++sequence).toString(16).padStart(12,"0"); }
function enrol():Enrolment {
 return {contract_version:1,purpose:"surface_push",action:"enrol",operation_id:op(),delegation_id:"example-delegation",expected_revision:0,approval_reference:"synthetic-operator-approval",install_id:"example-install",device_binding:"d".repeat(64),owner_binding:"e".repeat(64),grant_binding:"1".repeat(64),source_binding:"2".repeat(64),binding_id:"b".repeat(64),public_key:jwk,policy:{token_role:"widget",platform:"macos",apns_environment:"sandbox",target:{app_bundle_id:"dev.djconnect.mac",extension_bundle_id:"dev.djconnect.mac.track-insight-widget",widget_kind:"DJConnectSessionWidget"},activity_profile:null,external_content_allowed:false,original_grant_expires_at_ms:END,max_operations:100,max_events:10,max_challenges:10}};
}
function issuer() { return createSurfaceIssuer({env:{DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock}); }
type Handler=ReturnType<typeof issuer>;
async function call(handler:Handler,path:string,body:unknown,headers:Record<string,string>={}) {
 return handler(new Request("https://local.test"+ISSUER_PREFIX+path,{method:"POST",headers:{"content-type":"application/json",...headers},body:typeof body==="string"?body:JSON.stringify(body)}));
}
function input(action:Statement["action"],operation_id=op()):Statement { return {contract_version:1,purpose:"surface_push",action,operation_id,delegation_id:"example-delegation",delegation_revision:1,key_thumbprint:keyHash}; }
async function signed(payload:Statement,path:string=payload.action,signingKey=key) {
 return {payload,signature:base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},signingKey,signingBytes(ISSUER_PREFIX+path,payload)))};
}
async function enrolled(handler=issuer(),body=enrol()) { const result=await call(handler,"operator/enrol",body,{authorization:"Bearer "+OPERATOR}); expect(await result.clone().json()).toMatchObject({success:true,state:"enrolled"});return {handler,body}; }
async function prepared(handler=issuer()) {
 const context=await enrolled(handler), p=input("challenge"), r=await call(handler,"challenge",await signed(p));
 const challenge=await r.json() as {nonce:string;challenge_id:string;scope_digest:string;expires_at_ms:number}; expect(r.status).toBe(200);
 const issue:Statement={...p,action:"issue",challenge_id:challenge.challenge_id,nonce:challenge.nonce,scope_digest:challenge.scope_digest};
 return {...context,p,challenge,issue};
}
async function issued() {
 const p=await prepared(), r=await call(p.handler,"issue",await signed(p.issue));
 const result=await r.json() as {credential:string;capability_id:string}; expect(r.status,JSON.stringify(result)).toBe(200); expect(result.credential).toMatch(/^djcs_[A-Za-z0-9_-]{43}$/);
 return {...p,result};
}
async function count(table:string) { return env.DB.prepare("SELECT COUNT(*) AS n FROM "+table).first("n"); }
describe("actual D1 surface issuer with synthetic operator and ephemeral install keys",()=>{
 beforeAll(async()=>{
  for(const sql of (migration+"\n"+purposeMigration).split(";").filter(s=>s.replace(/--[^\n]*/g,"").trim())) await env.DB.prepare(sql).run();
  const pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair; key=pair.privateKey;
  const exported=(await crypto.subtle.exportKey("jwk",pair.publicKey)) as JsonWebKey; jwk={kty:"EC",crv:"P-256",x:exported.x!,y:exported.y!};keyHash=await thumbprint(jwk);
  otherKey=(await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair).privateKey;
 });
 beforeEach(async()=>{sequence=0;clock=NOW;for(const table of ["surface_push_operations","surface_push_targets","surface_push_capabilities","surface_push_issuer_operations","surface_push_operator_operations","surface_push_delegations"])await env.DB.prepare("DELETE FROM "+table).run();});
 it("admin-enrols an immutable scope then issues exactly one usable narrow credential",async()=>{
  const x=await issued(); expect(await count("surface_push_delegations")).toBe(1);expect(await count("surface_push_capabilities")).toBe(1);
  const row=await env.DB.prepare("SELECT * FROM surface_push_live_capabilities").first<Record<string,unknown>>();expect(row).toMatchObject({binding_id:"b".repeat(64),grant_binding:"1".repeat(64),source_binding:"2".repeat(64),delegation_revision:1,expires_at:END});
  const records=JSON.stringify(await env.DB.prepare("SELECT * FROM surface_push_issuer_operations").all());expect(records).not.toContain(x.result.credential);expect(records).not.toContain(x.challenge.nonce);
 });
 it.each([undefined,"Bearer djci_example","Bearer wrong"])("operator enrolment refuses %s without purpose authority",async authorization=>{
  const r=await call(issuer(),"operator/enrol",enrol(),authorization?{authorization}:{});expect([401,403]).toContain(r.status);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("authenticates exact bounded operator HMAC bytes and replays without extending the row",async()=>{
  const handler=issuer(), body=JSON.stringify(enrol()), timestamp=String(Math.floor(Date.now()/1000));
  const secret=await crypto.subtle.importKey("raw",new TextEncoder().encode(OPERATOR),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const digest=await crypto.subtle.sign("HMAC",secret,new TextEncoder().encode(timestamp+"."+body));const signature=[...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,"0")).join("");
  const headers={"x-djconnect-timestamp":timestamp,"x-djconnect-signature":"sha256="+signature};
  expect((await call(handler,"operator/enrol",body,headers)).status).toBe(200); const row=await env.DB.prepare("SELECT * FROM surface_push_delegations").first();
  expect(await (await call(handler,"operator/enrol",body,headers)).json()).toMatchObject({success:true,replayed:true,expires_at_ms:END});expect(await env.DB.prepare("SELECT * FROM surface_push_delegations").first()).toEqual(row);
  expect((await call(handler,"operator/enrol",body.replace("example-install","other-install"),headers)).status).toBe(401);
 });
 it("does not permit a policy/key update or operation digest reuse to replace an existing approval",async()=>{
  const body=enrol(),{handler}=await enrolled(issuer(),body);
  expect((await call(handler,"operator/enrol",{...body,policy:{...body.policy,max_events:11}},{authorization:"Bearer "+OPERATOR})).status).toBe(409);
  expect((await call(handler,"operator/enrol",{...body,operation_id:op(),owner_binding:"f".repeat(64)},{authorization:"Bearer "+OPERATOR})).status).toBe(409);
  expect(await count("surface_push_delegations")).toBe(1);
 });
 it.each(["d","kid","alg"])("rejects extra private/ambiguous JWK field %s",async field=>{
  const body=enrol();expect((await call(issuer(),"operator/enrol",{...body,public_key:{...jwk,[field]:"example"}},{authorization:"Bearer "+OPERATOR})).status).toBe(400);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("rejects an invalid EC point and undeclared activity export rights",async()=>{
  const body=enrol();expect((await call(issuer(),"operator/enrol",{...body,public_key:{...jwk,x:"A".repeat(43),y:"A".repeat(43)}},{authorization:"Bearer "+OPERATOR})).status).toBe(400);
  expect((await call(issuer(),"operator/enrol",{...body,policy:{...body.policy,external_content_allowed:true}},{authorization:"Bearer "+OPERATOR})).status).toBe(403);
 });
 it("malformed base64 in keys, signatures and nonces stays a bounded client error",async()=>{
  const body=enrol();expect((await call(issuer(),"operator/enrol",{...body,public_key:{...jwk,x:"A"}},{authorization:"Bearer "+OPERATOR})).status).toBe(400);
  const x=await prepared();expect((await call(x.handler,"challenge",{payload:input("challenge"),signature:"A"})).status).toBe(400);
  expect((await call(x.handler,"issue",await signed({...x.issue,nonce:"A"}))).status).toBe(400);expect(await count("surface_push_capabilities")).toBe(0);
 });
 it.each(["token_role","platform","apns_environment"] as const)("rejects an array enum for %s before persisting an operator approval",async field=>{
  const body=enrol();body.policy={...body.policy,token_role:"live_activity_update",platform:"ios",target:{app_bundle_id:"dev.djconnect.ios",attributes_type:"ExampleAttributes"}};
  const policy={...body.policy,[field]:[body.policy[field]]};
  expect((await call(issuer(),"operator/enrol",{...body,policy},{authorization:"Bearer "+OPERATOR})).status).toBe(400);
  expect(await count("surface_push_delegations")).toBe(0);
 });
 it("unenrolled proof and djci-only requests cannot self-enrol or bootstrap a credential",async()=>{
  const p=input("challenge");expect((await call(issuer(),"challenge",await signed(p))).status).toBe(401);
  await enrolled();expect((await call(issuer(),"challenge",{payload:p},{authorization:"Bearer djci_example"})).status).toBe(401);expect(await count("surface_push_capabilities")).toBe(0);
 });
 it("binds proof to the exact key, domain/action, route and scope",async()=>{
  const {handler}=await enrolled(), p=input("challenge");
  expect((await call(handler,"challenge",await signed(p,p.action,otherKey))).status).toBe(401);
  expect((await call(handler,"challenge",await signed(p,"status"))).status).toBe(401);
  const wrong=await signed(p);wrong.payload={...p,delegation_revision:2} as unknown as Statement;expect((await call(handler,"challenge",wrong)).status).toBe(400);
  expect(await count("surface_push_issuer_operations")).toBe(0);
 });
 it("returns a nonce once only; replay and restart do not extend or regenerate the challenge",async()=>{
  const x=await prepared(),row=await env.DB.prepare("SELECT * FROM surface_push_issuer_operations").first();clock=NOW+1000;
  const replay=await call(issuer(),"challenge",await signed(x.p));expect(replay.status).toBe(202);const body=await replay.json() as Record<string,unknown>;expect(body).not.toHaveProperty("nonce");expect(body.expires_at_ms).toBe(x.challenge.expires_at_ms);expect(await env.DB.prepare("SELECT * FROM surface_push_issuer_operations").first()).toEqual(row);
 });
 it("concurrent challenge requests disclose one nonce and reserve one durable challenge",async()=>{
  const {handler}=await enrolled(), p=input("challenge"), body=await signed(p);
  const responses=await Promise.all([call(handler,"challenge",body),call(handler,"challenge",body)]);expect(responses.map(r=>r.status).sort()).toEqual([200,202]);expect(await count("surface_push_issuer_operations")).toBe(1);
 });
 it("concurrent issuance consumes the challenge and returns at most one raw credential",async()=>{
  const x=await prepared(), body=await signed(x.issue);const results=await Promise.all([call(x.handler,"issue",body),call(x.handler,"issue",body)]);
  const replies=await Promise.all(results.map(r=>r.json())) as Record<string,unknown>[];expect(replies.filter(r=>typeof r.credential==="string")).toHaveLength(1);expect(await count("surface_push_capabilities")).toBe(1);
  expect(await env.DB.prepare("SELECT outcome FROM surface_push_issuer_operations WHERE kind='challenge'").first("outcome")).toBe("challenge_consumed");
 });
 it("lost credential response reconciles without bearer recovery, new issuance or renewal",async()=>{
  const x=await issued();const replay=await call(issuer(),"issue",await signed(x.issue));const body=await replay.json();expect(body).toMatchObject({success:false,state:"issued",credential_state:"unavailable",expires_at_ms:END});expect(body).not.toHaveProperty("credential");
  clock=NOW+300000;const r=await call(issuer(),"status",await signed({...x.p,action:"status"}));expect(await r.json()).toMatchObject({success:false,state:"issued",credential_state:"unavailable",expires_at_ms:END});expect(await count("surface_push_capabilities")).toBe(1);
 });
 it("one delegation cannot multiply its budget by starting another issuance operation",async()=>{
  const x=await issued();expect((await call(x.handler,"challenge",await signed(input("challenge")))).status).toBe(409);expect(await count("surface_push_capabilities")).toBe(1);
 });
 it("pre-reserved different challenges still race to at most one lifetime issuance per delegation",async()=>{
  const {handler}=await enrolled(),first=input("challenge"),second=input("challenge");
  const a=await (await call(handler,"challenge",await signed(first))).json() as {challenge_id:string;nonce:string;scope_digest:string};
  const b=await (await call(handler,"challenge",await signed(second))).json() as {challenge_id:string;nonce:string;scope_digest:string};
  const one:Statement={...first,action:"issue",challenge_id:a.challenge_id,nonce:a.nonce,scope_digest:a.scope_digest};
  const two:Statement={...second,action:"issue",challenge_id:b.challenge_id,nonce:b.nonce,scope_digest:b.scope_digest};
  const responses=await Promise.all([call(handler,"issue",await signed(one)),call(handler,"issue",await signed(two))]);expect(responses.map(r=>r.status).sort()).toEqual([200,409]);expect(await count("surface_push_capabilities")).toBe(1);
 });
 it("cannot use a wrong nonce or expired challenge even with the enrolled signing key",async()=>{
  const x=await prepared();expect((await call(x.handler,"issue",await signed({...x.issue,nonce:base64Url(new Uint8Array(32).buffer)}))).status).toBe(409);
  clock=NOW+120000;expect((await call(x.handler,"issue",await signed(x.issue))).status).toBe(409);expect(await count("surface_push_capabilities")).toBe(0);
 });
 it("a finite challenge budget is durable across handler restart",async()=>{
  const body=enrol();body.policy.max_challenges=1;await enrolled(issuer(),body);
  expect((await call(issuer(),"challenge",await signed(input("challenge")))).status).toBe(200);expect((await call(issuer(),"challenge",await signed(input("challenge")))).status).toBe(429);
 });
 it("withdrawal racing a held issue proof prevents capability creation",async()=>{
  const x=await prepared();expect((await call(x.handler,"withdraw",await signed(input("withdraw")))).status).toBe(200);
  expect((await call(x.handler,"issue",await signed(x.issue))).status).toBe(403);expect(await count("surface_push_capabilities")).toBe(0);
 });
 it("signed withdrawal remains possible after losing a credential or its original expiry",async()=>{
  const x=await issued();clock=END;const withdrawal=input("withdraw",op(clock));const r=await call(issuer(),"withdraw",await signed(withdrawal));expect(await r.json()).toMatchObject({success:true,state:"withdrawn",expires_at_ms:END});
  const status=await call(issuer(),"status",await signed({...x.p,action:"status"}));expect(await status.json()).toMatchObject({state:"withdrawn",success:false});expect(await count("surface_push_live_capabilities")).toBe(0);
 });
 it("operator can withdraw the exact delegation if the install key is lost",async()=>{
  await issued();const body={contract_version:1,purpose:"surface_push",action:"withdraw",operation_id:op(),delegation_id:"example-delegation",delegation_revision:1};
  expect((await call(issuer(),"operator/withdraw",body,{authorization:"Bearer "+OPERATOR})).status).toBe(200);expect(await count("surface_push_live_capabilities")).toBe(0);
 });
 it("operator operation IDs cannot cross from enrolment into withdrawal",async()=>{
  const body=enrol();await enrolled(issuer(),body);
  const revoke={contract_version:1,purpose:"surface_push",action:"withdraw",operation_id:body.operation_id,delegation_id:body.delegation_id,delegation_revision:1};
  expect((await call(issuer(),"operator/withdraw",revoke,{authorization:"Bearer "+OPERATOR})).status).toBe(409);
  expect(await env.DB.prepare("SELECT revoked_at FROM surface_push_delegations").first("revoked_at")).toBeNull();
 });
 it("D1 rollback cannot consume a challenge or retain a partial credential after insert failure",async()=>{
  const x=await prepared();await env.DB.prepare("CREATE TRIGGER synthetic_cap_failure BEFORE INSERT ON surface_push_capabilities BEGIN SELECT RAISE(ABORT,'synthetic_rollback'); END").run();
  try { expect((await call(x.handler,"issue",await signed(x.issue))).status).toBe(503); }
  finally { await env.DB.prepare("DROP TRIGGER synthetic_cap_failure").run(); }
  expect(await count("surface_push_capabilities")).toBe(0);
  expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM surface_push_issuer_operations WHERE kind='issue'").first("n")).toBe(0);
  expect(await env.DB.prepare("SELECT outcome FROM surface_push_issuer_operations WHERE kind='challenge'").first("outcome")).toBe("challenge_open");
 });
 it("a delegation withdrawal inside signature verification wins the subsequent issuance CAS",async()=>{
  const x=await prepared(), original=crypto.subtle.verify.bind(crypto.subtle);
  const verification=vi.spyOn(crypto.subtle,"verify").mockImplementation(async(...args)=>{
   const valid=await original(...args);
   const body={contract_version:1,purpose:"surface_push",action:"withdraw",operation_id:op(),delegation_id:x.body.delegation_id,delegation_revision:1};
   expect((await call(x.handler,"operator/withdraw",body,{authorization:"Bearer "+OPERATOR})).status).toBe(200);return valid;
  });
  try { expect((await call(x.handler,"issue",await signed(x.issue))).status).toBe(409); }
  finally { verification.mockRestore(); }
  expect(await count("surface_push_capabilities")).toBe(0);
 });
 it("does not extend an operation while waiting for purpose-key verification",async()=>{
  const {handler}=await enrolled(), original=crypto.subtle.verify.bind(crypto.subtle), p=input("challenge");
  const verification=vi.spyOn(crypto.subtle,"verify").mockImplementation(async(...args)=>{const valid=await original(...args);clock=NOW+300000;return valid;});
  try { expect((await call(handler,"challenge",await signed(p))).status).toBe(409); }
  finally { verification.mockRestore(); }
  expect(await count("surface_push_issuer_operations")).toBe(0);
 });
 it("an undeployed issuer secret fails closed without creating a delegation",async()=>{
  const handler=createSurfaceIssuer({env:{DB:env.DB} as AppEnv,now:()=>clock});
  expect((await call(handler,"operator/enrol",enrol(),{authorization:"Bearer "+OPERATOR})).status).toBe(500);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("old unbound capabilities are not upgraded by the new live principal view",async()=>{
  const x=await issued();await env.DB.prepare("UPDATE surface_push_capabilities SET delegation_id=NULL,binding_id=NULL").run();
  const handler=createSurfacePushHandler({db:env.DB,encryptionKey:AES,now:()=>clock});
  const r=await handler(new Request("https://local.test/v1/push/surface/status",{method:"POST",headers:{authorization:"Bearer "+x.result.credential,"content-type":"application/json"},body:"{}"}));expect(r.status).toBe(401);expect(await count("surface_push_live_capabilities")).toBe(0);
 });
 it("Live Activity update scope requires explicit compiled-profile admission and retains its exact iPhone role",async()=>{
  const body=enrol();body.policy={...body.policy,token_role:"live_activity_update",platform:"ios",target:{app_bundle_id:"dev.djconnect.ios",attributes_type:"ExampleAttributes"},activity_profile:"synthetic-closed/1",external_content_allowed:true};
  expect((await call(issuer(),"operator/enrol",body,{authorization:"Bearer "+OPERATOR})).status).toBe(403);
  const handler=createSurfaceIssuer({env:{DB:env.DB,DJCONNECT_RELAY_SECRET:OPERATOR} as AppEnv,now:()=>clock,admittedProfiles:["synthetic-closed/1"]});await enrolled(handler,body);
  const p=input("challenge"), challenge=await (await call(handler,"challenge",await signed(p))).json() as {challenge_id:string;nonce:string;scope_digest:string};
  const issue={...p,action:"issue" as const,...challenge}; // select closed challenge fields below
  const closedIssue:Statement={...p,action:"issue",challenge_id:issue.challenge_id,nonce:issue.nonce,scope_digest:issue.scope_digest};
  const result=await call(handler,"issue",await signed(closedIssue));expect(result.status).toBe(200);
  expect(await env.DB.prepare("SELECT role,platform,attributes_type,activity_profile,external_content_allowed FROM surface_push_live_capabilities").first()).toMatchObject({role:"live_activity_update",platform:"ios",attributes_type:"ExampleAttributes",activity_profile:"synthetic-closed/1",external_content_allowed:1});
 });
 it("the issued credential registers and sends only its exact enrolled binding; revoke stops pending transport",async()=>{
  const x=await issued(), transport=vi.fn<typeof fetch>().mockResolvedValue(new Response(null,{status:200}));
  const handler=createSurfacePushHandler({db:env.DB,encryptionKey:AES,now:()=>clock,fetcher:transport,authorizeProvider:async()=>{await call(x.handler,"withdraw",await signed(input("withdraw")));return "example.provider.jwt";}});
  const registration={contract_version:1,registration_id:"example-surface",generation:"example-grant-generation",revision:1,operation_id:op(),binding_id:"b".repeat(64),device_binding:"d".repeat(64),owner_binding:"e".repeat(64),expires_at_ms:END,token_role:"widget",platform:"macos",apns_environment:"sandbox",target:{instance_id:"instance",...enrol().policy.target},apns_token:"01".repeat(32)};
  const relay=(action:string,payload:unknown)=>handler(new Request("https://local.test/v1/push/surface/"+action,{method:"POST",headers:{authorization:"Bearer "+x.result.credential,"content-type":"application/json"},body:JSON.stringify(payload)}));
  expect((await relay("register",{...registration,binding_id:"f".repeat(64)})).status).toBe(403);expect((await relay("register",registration)).status).toBe(200);
  const event={contract_version:1,registration_id:registration.registration_id,generation:registration.generation,revision:1,operation_id:op(),binding_id:registration.binding_id,device_binding:registration.device_binding,owner_binding:registration.owner_binding,event:"widget_reload"};
  expect(await (await relay("event",event)).json()).toMatchObject({success:false,operation_state:"not_sent",state:"revoked"});expect(transport).not.toHaveBeenCalled();
  expect(await env.DB.prepare("SELECT ciphertext FROM surface_push_targets").first("ciphertext")).toBeNull();
 });
 it.each(["grant_binding","source_binding","scope_digest","binding_id"])("cannot widen a derived capability through a changed %s",async field=>{
  const x=await issued();await env.DB.prepare("UPDATE surface_push_capabilities SET "+field+"=?").bind("f".repeat(64)).run();expect(await count("surface_push_live_capabilities")).toBe(0);
  const handler=createSurfacePushHandler({db:env.DB,encryptionKey:AES,now:()=>clock});
  const coordinates={contract_version:1,registration_id:"example-surface",generation:"example-generation",revision:1,operation_id:op(),binding_id:"b".repeat(64),device_binding:"d".repeat(64),owner_binding:"e".repeat(64)};
  expect((await handler(new Request("https://local.test/v1/push/surface/status",{method:"POST",headers:{authorization:"Bearer "+x.result.credential,"content-type":"application/json"},body:JSON.stringify(coordinates)}))).status).toBe(401);
 });
 it("strict closed messages reject duplicates, unknown policy fields and browser transport",async()=>{
  const body=enrol();expect((await call(issuer(),"operator/enrol",JSON.stringify(body).replace('"expected_revision":0','"expected_revision":0,"expected_revision":0'),{authorization:"Bearer "+OPERATOR})).status).toBe(400);
  expect((await call(issuer(),"operator/enrol",{...body,policy:{...body.policy,broadcast:true}},{authorization:"Bearer "+OPERATOR})).status).toBe(400);
  expect((await call(issuer(),"operator/enrol",body,{authorization:"Bearer "+OPERATOR,origin:"https://example.invalid"})).status).toBe(403);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("original operation expiry after body reading cannot create a delegation",async()=>{
  const body=enrol(),stream=new ReadableStream<Uint8Array>({pull(controller){clock=NOW+300000;controller.enqueue(new TextEncoder().encode(JSON.stringify(body)));controller.close();}},{highWaterMark:0});
  const r=await issuer()(new Request("https://local.test"+ISSUER_PREFIX+"operator/enrol",{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+OPERATOR},body:stream}));expect(r.status).toBe(409);expect(await count("surface_push_delegations")).toBe(0);
 });
 it("verifies separately generated public signing vectors in actual workerd with no private fixture key",async()=>{
  const key=await crypto.subtle.importKey("jwk",vectors.public_key,{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
  expect(await thumbprint(vectors.public_key as Enrolment["public_key"])).toBe(vectors.key_thumbprint);
  for(const v of vectors.vectors){
   expect(new TextDecoder().decode(signingBytes(v.path,v.payload as unknown as Statement))).toBe(v.signing_bytes_utf8);
   const signature=Uint8Array.from(atob(v.signature.replaceAll("-","+").replaceAll("_","/")),c=>c.charCodeAt(0));
   expect(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,signature,new TextEncoder().encode(v.signing_bytes_utf8))).toBe(true);
   expect(await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,signature,new TextEncoder().encode(v.signing_bytes_utf8+" "))).toBe(false);
  }
 });
 it("published signing bytes are closed deterministic domain/method/path plus the exact statement",()=>{
  const p=input("status","019a0000-0000-7000-8000-000000000001");
  expect(new TextDecoder().decode(signingBytes(ISSUER_PREFIX+"status",p))).toBe('["djc-surface-issuer/1","POST","/v1/push/surface/issuer/status",'+canonical(p)+']');
 });
});
