import {env} from "cloudflare:test";
import {expect,it} from "vitest";
import schema from "../../../src/watch-lifecycle/preference-schema.sql?raw";
it("revocation after D1 commit suppresses enrollment acknowledgement and independent admission", async () => {
  const db = env.DB;
  for (const sql of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(sql).run();
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
