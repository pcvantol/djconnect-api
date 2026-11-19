import { env } from "cloudflare:test";
import { beforeAll, beforeEach, afterEach, expect, it, vi } from "vitest";
import migration from "../migrations/0009_surface_push.sql?raw";
import purposeMigration from "../migrations/0010_surface_delegations.sql?raw";
import { base64Url } from "../src/crypto";
import type { AppEnv } from "../src/types";
import { createSurfaceService, type SurfaceService } from "../src/surface-push/composition";
import { signingBytes, thumbprint, type Enrolment, type Statement } from "../src/surface-push/issuer-wire";

const NOW = Math.floor(Date.now()/1000)*1000, END = NOW+900000, OPERATOR = "example-composition-operator";
let key: CryptoKey, jwk: Enrolment["public_key"], keyHash: string, pem: string, sequence = 0;
const services: SurfaceService[] = [];
function op() { return NOW.toString(16).padStart(12,"0").replace(/^(.{8})(.{4})$/,"$1-$2")+"-7000-8000-"+(++sequence).toString(16).padStart(12,"0"); }
function configuration(): AppEnv { return { DB:env.DB, APNS_TEAM_ID:"TEAM123456", APNS_KEY_ID:"KEY1234567", APNS_PRIVATE_KEY:pem,
    APNS_TOKEN_ENCRYPTION_KEY:btoa("0123456789abcdef0123456789abcdef"), DJCONNECT_RELAY_SECRET:OPERATOR,
    APNS_ENVIRONMENT:"sandbox", APNS_TOPIC_IOS:"dev.djconnect.ios", APNS_TOPIC_MACOS:"dev.djconnect.mac", APNS_TOPIC_WATCHOS:"dev.djconnect.watch" }; }
function service(config = configuration(), fetcher: typeof fetch = vi.fn(async()=>new Response("{}"))) {
    const instance = createSurfaceService({env:config, now:()=>NOW, fetcher}); services.push(instance); return instance;
}
function call(s: SurfaceService, path: string, body: unknown, authorization?: string, config?: AppEnv) {
    return s.handle(new Request("https://local.test/v1/push/surface/"+path,{method:"POST",headers:{"content-type":"application/json",...(authorization?{authorization}: {})},body:JSON.stringify(body)}),config);
}
async function signed(payload: Statement) { return {payload,signature:base64Url(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,signingBytes("/v1/push/surface/issuer/"+payload.action,payload)))}; }
async function admitted(s: SurfaceService) {
    const body: Enrolment = {contract_version:1,purpose:"surface_push",action:"enrol",operation_id:op(),delegation_id:"example-composition",expected_revision:0,
        approval_reference:"synthetic-only",install_id:"example-install",device_binding:"d".repeat(64),owner_binding:"e".repeat(64),grant_binding:"1".repeat(64),source_binding:"2".repeat(64),binding_id:"b".repeat(64),public_key:jwk,
        policy:{token_role:"widget",platform:"ios",apns_environment:"sandbox",target:{app_bundle_id:"dev.djconnect.ios",extension_bundle_id:"dev.djconnect.ios.track-insight-widget",widget_kind:"DJConnectSessionWidget"},activity_profile:null,external_content_allowed:false,original_grant_expires_at_ms:END,max_operations:4,max_events:2,max_challenges:1}};
    expect((await call(s,"issuer/operator/enrol",body,"Bearer "+OPERATOR)).status).toBe(200);
    const original: Statement = {contract_version:1,purpose:"surface_push",action:"challenge",operation_id:op(),delegation_id:body.delegation_id,delegation_revision:1,key_thumbprint:keyHash};
    const challenge = await (await call(s,"issuer/challenge",await signed(original))).json() as {challenge_id:string;nonce:string;scope_digest:string};
    const issue: Statement = {...original,action:"issue",...challenge};
    // Only the three challenge fields belong in the signed issue statement.
    const exact: Statement = {...original,action:"issue",challenge_id:issue.challenge_id,nonce:issue.nonce,scope_digest:issue.scope_digest};
    const result = await (await call(s,"issuer/issue",await signed(exact))).json() as {success:boolean;credential:string};
    expect(result.success).toBe(true); return result.credential;
}
function registration() { return {contract_version:1,registration_id:"example-widget",generation:"original-generation",revision:1,operation_id:op(),binding_id:"b".repeat(64),device_binding:"d".repeat(64),owner_binding:"e".repeat(64),expires_at_ms:END,token_role:"widget",platform:"ios",apns_environment:"sandbox",target:{instance_id:"original-widget",app_bundle_id:"dev.djconnect.ios",extension_bundle_id:"dev.djconnect.ios.track-insight-widget",widget_kind:"DJConnectSessionWidget"},apns_token:"01".repeat(32)}; }
function coordinate(r: ReturnType<typeof registration>) { return {contract_version:r.contract_version,registration_id:r.registration_id,generation:r.generation,revision:r.revision,operation_id:op(),binding_id:r.binding_id,device_binding:r.device_binding,owner_binding:r.owner_binding}; }
beforeAll(async()=>{
    for(const sql of (migration+"\n"+purposeMigration).split(";").filter(s=>s.replace(/--[^\n]*/g,"").trim())) await env.DB.prepare(sql).run();
    const purpose = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair;
    key = purpose.privateKey; const j = await crypto.subtle.exportKey("jwk",purpose.publicKey) as JsonWebKey; jwk={kty:"EC",crv:"P-256",x:j.x!,y:j.y!};keyHash=await thumbprint(jwk);
    const provider = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]) as CryptoKeyPair;
    const bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8",provider.privateKey) as ArrayBuffer);
    const label = "PRIVATE KEY"; pem="-----BEGIN "+label+"-----\n"+btoa(String.fromCharCode(...bytes))+"\n-----END "+label+"-----";
});
beforeEach(async()=>{sequence=0;for(const table of ["surface_push_operations","surface_push_targets","surface_push_capabilities","surface_push_issuer_operations","surface_push_operator_operations","surface_push_delegations"])await env.DB.prepare("DELETE FROM "+table).run();});
afterEach(()=>{for(const s of services.splice(0))s.close();vi.restoreAllMocks();});
it("composes actual issuer, D1 registration, cached provider, status and terminal revoke",async()=>{
    const transport = vi.fn(async()=>new Response("{}")), config=configuration(), s=service(config,transport), bearer="Bearer "+await admitted(s), r=registration();
    expect((await call(s,"register",r,bearer)).status).toBe(200);
    const signing=vi.spyOn(crypto.subtle,"sign");
    for(let i=0;i<2;i++)expect(await (await call(s,"event",{...coordinate(r),event:"widget_reload"},bearer,{...config})).json()).toMatchObject({success:true,operation_state:"provider_accepted"});
    expect(signing).toHaveBeenCalledTimes(1);expect(transport).toHaveBeenCalledTimes(2);
    const calls=transport.mock.calls as unknown as [string,RequestInit][];
    expect(calls[0]![0]).toBe("https://api.sandbox.push.apple.com/3/device/"+r.apns_token);
    expect(calls[0]![1].headers).toMatchObject({"apns-topic":"dev.djconnect.ios.push-type.widgets","apns-push-type":"widgets"});
    expect(calls[1]![1].headers).toEqual(calls[0]![1].headers);
    const revoke=coordinate(r);expect(await(await call(s,"revoke",revoke,bearer)).json()).toMatchObject({success:true,state:"revoked"});
    expect((await call(s,"status",revoke,bearer)).status).toBe(200);expect(transport).toHaveBeenCalledTimes(2);
    expect(await env.DB.prepare("SELECT ciphertext FROM surface_push_targets").first("ciphertext")).toBeNull();
});
it("operator and relay routes keep their separate authentication",async()=>{
    const s=service();
    expect((await call(s,"issuer/operator/enrol",{},"Bearer djci_example")).status).toBe(403);
    expect((await call(s,"register",{},"Bearer "+OPERATOR)).status).toBe(401);
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM surface_push_delegations").first("n")).toBe(0);
});
it("bad provider configuration cannot block registration, revocation or operator withdrawal",async()=>{
    const config=configuration();config.APNS_PRIVATE_KEY="unconfigured";const transport=vi.fn(async()=>new Response("{}")),s=service(config,transport),bearer="Bearer "+await admitted(s),r=registration();
    expect((await call(s,"register",r,bearer)).status).toBe(200);expect((await call(s,"revoke",coordinate(r),bearer)).status).toBe(200);
    expect((await call(s,"issuer/operator/withdraw",{contract_version:1,purpose:"surface_push",action:"withdraw",operation_id:op(),delegation_id:"example-composition",delegation_revision:1},"Bearer "+OPERATOR)).status).toBe(200);
    expect(transport).not.toHaveBeenCalled();
});
it("retiring or changing the original identity rejects pending provider authorization before any send",async()=>{
    const config=configuration(),transport=vi.fn(async()=>new Response("{}")),s=service(config,transport),bearer="Bearer "+await admitted(s),r=registration();await call(s,"register",r,bearer);
    const sign=crypto.subtle.sign.bind(crypto.subtle);
    vi.spyOn(crypto.subtle,"sign").mockImplementation(async(...args)=>{config.APNS_KEY_ID="OTHERKEY01";return sign(...args);});
    await expect(call(s,"event",{...coordinate(r),event:"widget_reload"},bearer)).rejects.toMatchObject({code:"surface_service_unavailable"});
    expect(transport).not.toHaveBeenCalled();expect(s.matches(config)).toBe(false);
    expect(await env.DB.prepare("SELECT outcome FROM surface_push_operations WHERE kind='event'").first("outcome")).toBe("not_sent");
});
it("close permanently retires an otherwise matching service",async()=>{
    const config=configuration(),s=service(config);expect(s.matches({...config})).toBe(true);s.close();expect(s.matches(config)).toBe(false);
    await expect(call(s,"status",{})).rejects.toMatchObject({code:"surface_service_unavailable"});
});
