import schema from "../../../src/watch-lifecycle/preference-schema.sql?raw";
import {env, SELF} from "cloudflare:test";
import {expect,it} from "vitest";

it("blocks pending, mismatched and same-epoch rolled-back D1 observations", async () => {
  const ns = (env as unknown as {ACTOR: DurableObjectNamespace}).ACTOR;
  const actor = ns.get(ns.idFromName("restore"));
  const rpc = async (action: string, payload = {}) =>
    (await actor.fetch("http://fixture/" + action, {method:"POST",body:JSON.stringify(payload)})).json();
  const db = env.DB;
  await db.prepare("CREATE TABLE fixture(epoch INTEGER, revision INTEGER, operation TEXT, body_hash TEXT, enabled INTEGER, sealed INTEGER)").run();
  await db.prepare("INSERT INTO fixture VALUES (1,0,NULL,NULL,0,0)").run();
  const read = () => db.prepare("SELECT revision,operation,body_hash,enabled,sealed FROM fixture WHERE epoch=1").first();
  const prev = await read();
  const on = {revision:1, operation:"on", body_hash:"a".repeat(64), enabled:1,sealed:0};
  const off = {revision:2, operation:"off", body_hash:"b".repeat(64), enabled:0,sealed:0};
  const write = async (state: typeof on) => {
    await db.prepare("UPDATE fixture SET revision=?,operation=?,body_hash=?,enabled=?,sealed=? WHERE epoch=1")
      .bind(state.revision,state.operation,state.body_hash,state.enabled,state.sealed).run();
  };
  expect(await rpc("dispatch",on)).toBe(false);
  expect(await rpc("init")).toBe(true);
  expect(await rpc("begin",{previous:prev,next:on})).toBe(true);
  await write(on);
  expect(await rpc("dispatch",(await read())!)).toBe(false);
  expect(await rpc("confirm",{...on,body_hash:"c".repeat(64)})).toBe(false);
  expect(await rpc("dispatch",(await read())!)).toBe(false);
  expect(await rpc("confirm",(await read())!)).toBe(true);
  expect(await rpc("dispatch",(await read())!)).toBe(true);
  expect(await rpc("begin",{previous:on,next:off})).toBe(true);
  expect(await rpc("dispatch",(await read())!)).toBe(false);
  await write(off);
  expect(await rpc("confirm",(await read())!)).toBe(true);
  await write(on);
  expect(await rpc("dispatch",(await read())!)).toBe(false);
  expect(await rpc("init")).toBe(false);
  expect(await rpc("begin",{previous:on,next:off})).toBe(false);
});

it("does not route restored D1 to the old actor across a generation change", async () => {
  const rpc = async (path: string, body = {}) => (await SELF.fetch("http://fixture/"+path, {
    method:"POST",body:JSON.stringify(body),
  })).json();
  const baseline = {revision:0,operation:null,body_hash:null,enabled:0,sealed:0};
  const on = {revision:1,operation:"on",body_hash:"a".repeat(64),enabled:1,sealed:0};
  for (const suffix of ["", "?legacy=1"]) {
    expect(await rpc("init"+suffix)).toBe(true);
    expect(await rpc("begin"+suffix,{previous:baseline,next:on})).toBe(true);
    expect(await rpc("confirm"+suffix,on)).toBe(true);
  }
  await env.DB.prepare("CREATE TABLE epoch_fixture(epoch INTEGER, revision INTEGER, operation TEXT, body_hash TEXT, enabled INTEGER, sealed INTEGER)").run();
  await env.DB.prepare("INSERT INTO epoch_fixture VALUES (2,0,NULL,NULL,0,0)").run();
  expect(await rpc("advance")).toBe(true);
  expect(await rpc("dispatch?epoch=2",baseline)).toBe(false);
  await env.DB.prepare("UPDATE epoch_fixture SET epoch=1,revision=1,operation='on',body_hash=?,enabled=1").bind(on.body_hash).run();
  const {epoch,...observed} = (await env.DB.prepare("SELECT * FROM epoch_fixture").first())!;
  expect(await rpc("dispatch?epoch="+epoch,observed)).toBe(false);
  // Counterproof: the previous generation-specific actor still has a matching opt-in.
  expect(await rpc("dispatch?epoch=1&legacy=1",observed)).toBe(true);
});

it("blocks a normal relay after revoke wins over a paused D1 observation", async () => {
  const db = env.DB;
  for (const sql of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(sql).run();
  await db.prepare("INSERT INTO watch_lifecycle_issuer VALUES ('lab',1,?,'watch-lifecycle',1,NULL)").bind("a".repeat(64)).run();
  const key = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const raw = await crypto.subtle.exportKey("pkcs8",key.privateKey);
  const pem = "-----BEGIN PRIVATE KEY-----\n"+btoa(String.fromCharCode(...new Uint8Array(raw)))+"\n-----END PRIVATE KEY-----";
  const registration = {apns_environment:"sandbox",topic:"dev.djconnect.ios.watch",apns_token:"a".repeat(64),
    apns_token_hash:Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode("a".repeat(64)))),x=>x.toString(16).padStart(2,"0")).join("")};
  for (const receiver of ["control","revoked"]) {
    const rpc = async (path: string, body = {}) => (await SELF.fetch("http://fixture/"+path+"?receiver="+receiver,{
      method:"POST",body:JSON.stringify(body),
    })).json();
    const baseline = {revision:0,operation:null,body_hash:null,enabled:0,sealed:0};
    const on = {revision:1,operation:"on",body_hash:"a".repeat(64),enabled:1,sealed:0};
    await db.prepare("INSERT INTO watch_lifecycle_preference(installation,receiver,epoch,incarnation,revision,operation,body_hash,enabled) VALUES ('lab',?,1,'pair-1',1,'on',?,1)").bind(receiver,on.body_hash).run();
    expect(await rpc("init")).toBe(true);
    expect(await rpc("begin",{previous:baseline,next:on})).toBe(true);
    expect(await rpc("confirm",on)).toBe(true);
    const pause = receiver==="revoked";
    const send = rpc("send",{pause,registration,env:{APNS_TEAM_ID:"lab",APNS_KEY_ID:"lab",APNS_PRIVATE_KEY:pem}});
    if (pause) {
      await expect.poll(() => Promise.race([rpc("ready"),send.then(()=>{throw Error("provider preparation ended early");})])).toBe(true);
      expect(await rpc("revoke")).toBe(true);
      await rpc("resume");
    }
    expect(await send).toBe(pause ? 0 : 200);
    expect(await rpc("count")).toBe(pause ? 0 : 1);
  }
});
