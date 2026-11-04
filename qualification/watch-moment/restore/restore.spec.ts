import momentSchema from "../../../src/watch-moment/schema.sql?raw";
import proposal from "../../../docs/push/watch-moment-alert-proposal-v1.json";
import {frameLifecycleProof} from "../../../src/watch-lifecycle/proof";
import {encryptSecret, sha256Hex} from "../../../src/crypto";
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
  for (const sql of momentSchema.split(";").map(v=>v.trim()).filter(Boolean)) await db.prepare(sql).run();
  await db.prepare(`CREATE TABLE registrations(id TEXT PRIMARY KEY, apns_token_hash TEXT, ha_install_id TEXT, ha_user_hash TEXT,
    device_id TEXT, topic TEXT, apns_environment TEXT, disabled INTEGER, invalid INTEGER, last_error_code TEXT,
    client_type TEXT, app_bundle_id TEXT, categories_json TEXT, apns_token_ciphertext TEXT, apns_token_nonce TEXT)`).run();
  const key = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},true,["sign","verify"]);
  const raw = await crypto.subtle.exportKey("pkcs8",key.privateKey);
  const pem = "-----BEGIN PRIVATE KEY-----\n"+btoa(String.fromCharCode(...new Uint8Array(raw)))+"\n-----END PRIVATE KEY-----";
  const spki = await crypto.subtle.exportKey("spki",key.publicKey);
  const hex = (b:ArrayBuffer) => Array.from(new Uint8Array(b),x=>x.toString(16).padStart(2,"0")).join("");
  const fingerprint = hex(await crypto.subtle.digest("SHA-256",spki));
  await db.prepare("INSERT INTO watch_lifecycle_issuer VALUES ('lab',1,?,'watch-lifecycle',1,?)").bind(fingerprint,hex(spki)).run();
  for (const receiver of ["control","revoked"]) {
    const rpc = async (path: string, body = {}) => (await SELF.fetch("http://fixture/"+path+"?receiver="+receiver+"&fingerprint="+fingerprint,{
      method:"POST",body:JSON.stringify(body),
    })).json();
    const baseline = {revision:0,operation:null,body_hash:null,enabled:0,sealed:0};
    const on = {revision:1,operation:"on",body_hash:"a".repeat(64),enabled:1,sealed:0};
    await db.prepare("INSERT INTO watch_lifecycle_preference(installation,receiver,epoch,incarnation,revision,operation,body_hash,enabled) VALUES ('lab',?,1,'pair-1',1,'on',?,1)").bind(receiver,on.body_hash).run();
    expect(await rpc("init")).toBe(true);
    expect(await rpc("begin",{previous:baseline,next:on})).toBe(true);
    expect(await rpc("confirm",on)).toBe(true);
    const now = Date.now();
    const event = {...proposal.shared_synthetic_fixture.event,ha_install_id:"lab",device_id:receiver,event_id:receiver,
      moment_id:"moment-"+receiver,created_at_ms:now-1000,expires_at_ms:now+30000};
    const encryptionKey = btoa("0123456789abcdef0123456789abcdef");
    const encrypted = await encryptSecret("a".repeat(64), encryptionKey);
    const registration = {id:receiver, ha_install_id:"lab", ha_user_hash:event.ha_user_hash,device_id:receiver,
      apns_environment:"sandbox",topic:"dev.djconnect.ios.watch",app_bundle_id:"dev.djconnect.ios.watch",client_type:"watchos",
      disabled:0, invalid:0,categories_json:'["dj_moments_v1"]',apns_token:null,apns_token_ciphertext:encrypted.ciphertext,apns_token_nonce:encrypted.nonce,apns_token_hash:await sha256Hex("a".repeat(64))};
    await db.prepare("INSERT INTO registrations VALUES(?,?,?,?,?,?,?,0,0,NULL,?,?,?,?,?)")
      .bind(receiver,registration.apns_token_hash,"lab",event.ha_user_hash,receiver,registration.topic,"sandbox","watchos",registration.topic,registration.categories_json,encrypted.ciphertext,encrypted.nonce).run();
    const pause = receiver==="revoked";
    const send = rpc("send",{pause,event,registration,env:{APNS_TEAM_ID:"lab",APNS_KEY_ID:"lab",APNS_PRIVATE_KEY:pem,APNS_TOKEN_ENCRYPTION_KEY:encryptionKey}});
    if (pause) {
      await expect.poll(() => Promise.race([rpc("ready"),send.then(()=>{throw Error("provider preparation ended early");})])).toBe(true);
      const t = Math.floor(Date.now()/1000);
      const body = new TextEncoder().encode(JSON.stringify({installation:"lab",receiver,incarnation:"pair-1",epoch:1,
        key_fingerprint:fingerprint,audience:"lab",action:"retire",operation:"revoke",expiry:t+25}));
      const signature = await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key.privateKey,await frameLifecycleProof(body,"lab",t));
      const encoded = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
      const response = await SELF.fetch("http://fixture/revoke?receiver="+receiver+"&fingerprint="+fingerprint,{
        method:"POST",body,headers:{"content-type":"application/json","djc-watch-lifecycle-signature":encoded},
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({outcome:"committed"});
      await rpc("resume");
    }
    expect(await send).toBe(pause ? "unknown" : "provider_accepted");
    expect(await rpc("count")).toBe(pause ? 0 : 1);
  }
});
