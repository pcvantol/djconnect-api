import {WatchEnrollmentAuthority} from "../../../src/watch-lifecycle/enrollment-authority";
import {env, runInDurableObject} from "cloudflare:test";
import {createOwnedInitialWatchEnrollment, createSignedInitialWatchEnrollment, frameInitialWatchAdmission} from "../../../src/watch-lifecycle/owned-enrollment";
import {watchRestoreActorName} from "../../../src/watch-lifecycle/dispatch-identity";
import {WatchRestoreAuthority} from "../../../src/watch-lifecycle/restore-authority";
import {beforeAll,expect,it} from "vitest";
import schema from "../../../src/watch-lifecycle/preference-schema.sql?raw";
beforeAll(async () => {
  for (const sql of schema.trim().split(/;\s*(?=CREATE)/)) await env.DB.prepare(sql).run();
});

it("revocation after D1 commit suppresses enrollment acknowledgement and independent admission", async () => {
  const db = env.DB;
  const ns = (env as unknown as {ACTOR:DurableObjectNamespace}).ACTOR;
  const actor = ns.get(ns.idFromName("home"));
  const send = (path:string, body:unknown, signature?:string) => actor.fetch("http://fixture/"+path,{
    method:"POST", body:JSON.stringify(body), headers:{"content-type":"application/json",...(signature?{"djc-watch-lifecycle-signature":signature}:{})},
  });
  const key = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const spki = await crypto.subtle.exportKey("spki",key.publicKey);
  const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",spki)),b=>b.toString(16).padStart(2,"0")).join("");
  const expiry = Math.floor(Date.now()/1000)+25;
  const intent = {audience:"lab",installation:"home",operator_binding:"a".repeat(64),restore_fence:"b".repeat(64),
    key_fingerprint:fingerprint,expected_epoch:0,expiry};
  const args = {intent,spki:Array.from(new Uint8Array(spki))};
  expect((await send("issue",args)).status).toBe(403);
  expect(await (await send("authorize",intent)).json()).toBe(true);
  expect((await send("issue",{...args,intent:{...intent,restore_fence:"c".repeat(64)}})).status).toBe(403);
  const issued = await send("issue",args);
  expect(issued.status).toBe(201);
  const {nonce,challenge_id}=await issued.json<{nonce:string;challenge_id:string}>();
  const parts=["DJC-WATCH-ENROLLMENT-V1\0"];
  for(const field of ["lab","home",fingerprint,"watch-lifecycle","0","1",nonce,String(expiry)])
    parts.push(String.fromCharCode(0,0,0,field.length),field);
  const raw = await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,new TextEncoder().encode(parts.join("")));
  const signature=btoa(String.fromCharCode(...new Uint8Array(raw))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  const pending=send("redeem",{challenge_id,nonce},signature);
  await expect.poll(async()=> (await send("ready",{})).json()).toBe(true);
  expect(await db.prepare("SELECT count(*) AS n FROM watch_lifecycle_issuer WHERE active=1").first("n")).toBe(1);
  expect(await (await send("revoke",intent.operator_binding)).json()).toBe(true);
  expect(await (await send("admitted",intent)).json()).toBe(false);
  await send("resume",{});
  const reply=await pending;
  expect(reply.status).toBe(503);
  expect(await reply.json()).toEqual({error:"watch_enrollment_outcome_unknown"});
  expect(await (await send("authorize",intent)).json()).toBe(false);
  expect(await (await send("admitted",intent)).json()).toBe(false);
});

it("issues and redeems only the explicitly prepared first scope on its stable owner", async () => {
  const db = env.DB;
  const ns = (env as unknown as {ACTOR:DurableObjectNamespace}).ACTOR;
  const key = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki",key.publicKey));
  const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",spki)), b=>b.toString(16).padStart(2,"0")).join("");
  const scope = {installation:"owned-home",receiver:"watch",incarnation:"pair-1",epoch:1,key_fingerprint:fingerprint};
  const expiry = Math.floor(Date.now()/1000)+25;
  const intent = {audience:"lab",installation:scope.installation,operator_binding:"d".repeat(64),
    restore_fence:"b".repeat(64),key_fingerprint:fingerprint,expected_epoch:0,expiry};
  const actor = ns.getByName((await watchRestoreActorName(scope))!);
  const request = () => new Request("https://fixture.invalid/issue",{method:"POST"});
  await runInDurableObject(actor, async (_instance,ctx) => {
    let witness = false;
    let interrupt = false;
    let witnessChecks = 0;
    const owner = {db,actor:ctx,namespace:ns,
      assertOperatorCurrent() {},
      assertRestoreWitnessCurrent() {
        if (!witness || (interrupt && ++witnessChecks === 2)) throw new Error("fixture witness unavailable");
      },
    };
    expect(await createOwnedInitialWatchEnrollment(undefined,scope,intent,spki)).toBeNull();
    expect(await createOwnedInitialWatchEnrollment(owner,{...scope,receiver:"different"},intent,spki)).toBeNull();
    const enrollment = await createOwnedInitialWatchEnrollment(owner,scope,intent,spki);
    expect(enrollment).not.toBeNull();
    expect(await enrollment!.prepare()).toBe(false);
    witness = true;
    expect((await enrollment!.issue(request())).status).toBe(403);
    const conflicting = { ...intent, operator_binding: "f".repeat(64) };
    expect(await new WatchEnrollmentAuthority(ctx.storage, scope.installation)
      .authorize({ ...conflicting, restore_fence: "c".repeat(64) })).toBe(true);
    const blocked = await createOwnedInitialWatchEnrollment(owner,scope,conflicting,spki);
    expect(await blocked!.prepare()).toBe(false);
    expect(new WatchRestoreAuthority(ctx.storage).classifyObservation(scope,
      {revision:0,operation:null,body_hash:null,enabled:0,sealed:0})).toBe("unavailable");
    interrupt = true;
    expect(await enrollment!.prepare()).toBe(false);
    interrupt = false;
    const freshIntent = { ...intent, operator_binding: "e".repeat(64) };
    const algorithm = { name: "ECDSA", namedCurve: "P-256" };
    const signAlgorithm = { name: "ECDSA", hash: "SHA-256" };
    const operator = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const restore = await crypto.subtle.generateKey(algorithm, true, ["sign", "verify"]);
    const signedOwner = { ...owner, trustedAdmissionKeys: {
      operator: new Uint8Array(await crypto.subtle.exportKey("spki", operator.publicKey)),
      restore: new Uint8Array(await crypto.subtle.exportKey("spki", restore.publicKey)),
    }};
    const sign = async (role: "operator" | "restore", key: CryptoKey) =>
      new Uint8Array(await crypto.subtle.sign(signAlgorithm, key, frameInitialWatchAdmission(role, scope, freshIntent)));
    const signatures = { operator: await sign("operator", operator.privateKey), restore: await sign("restore", restore.privateKey) };
    expect(await createSignedInitialWatchEnrollment(signedOwner, scope, freshIntent, spki,
      { ...signatures, restore: await sign("restore", operator.privateKey) })).toBeNull();
    expect(await createSignedInitialWatchEnrollment(signedOwner, { ...scope, receiver: "other-watch" },
      freshIntent, spki, signatures)).toBeNull();
    const retry = await createSignedInitialWatchEnrollment(signedOwner, scope, freshIntent, spki, signatures);
    expect(await retry!.prepare()).toBe(true);
    expect(await retry!.prepare()).toBe(true);
    const issued = await retry!.issue(request());
    expect(issued.status).toBe(201);
    const {nonce,challenge_id} = await issued.json<{nonce:string;challenge_id:string}>();
    const parts = ["DJC-WATCH-ENROLLMENT-V1\0"];
    for (const field of ["lab",scope.installation,fingerprint,"watch-lifecycle","0","1",nonce,String(expiry)])
      parts.push(String.fromCharCode(0,0,0,field.length),field);
    const signed = await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,new TextEncoder().encode(parts.join("")));
    const signature = btoa(String.fromCharCode(...new Uint8Array(signed))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    const redeem = () => retry!.redeem(new Request("https://fixture.invalid/redeem",{
      method:"POST",body:JSON.stringify({challenge_id,nonce}),
      headers:{"content-type":"application/json","djc-watch-lifecycle-signature":signature},
    }));
    witness = false;
    expect((await redeem()).status).toBe(403);
    witness = true;
    const receipt = await redeem();
    expect(receipt.status).toBe(200);
    expect(await receipt.json()).toEqual({installation:scope.installation,epoch:1,key_fingerprint:fingerprint,scope:"watch-lifecycle"});
    expect((await redeem()).status).toBe(403);
    expect(new WatchRestoreAuthority(ctx.storage).classifyObservation(scope,
      {revision:0,operation:null,body_hash:null,enabled:0,sealed:0})).toBe("confirmed");
  });
});
