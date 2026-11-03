import { env } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../src/watch-lifecycle/preference-schema.sql?raw";
import { frameLifecycleProof } from "../src/watch-lifecycle/proof";
import { recoverWatchReceiver } from "../src/watch-lifecycle/recovery";
import { applyWatchPairing } from "../src/watch-lifecycle/pairing";

it("recovers the exact predecessor once without carrying its opt-in across epochs", async () => {
	const db = env.DB;
	for (const statement of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(statement).run();
	const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign","verify"]);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
	const hex = (b: ArrayBuffer) => Array.from(new Uint8Array(b), n => n.toString(16).padStart(2, "0")).join("");
	const fingerprint = hex(await crypto.subtle.digest("SHA-256", spki));
	const now = Number(await db.prepare("SELECT unixepoch()").first("unixepoch()"));
	await db.prepare("INSERT INTO watch_lifecycle_issuer(installation,epoch,key_fingerprint,scope,active) VALUES ('home',2,?,'watch-lifecycle',1)").bind(fingerprint).run();
	await db.prepare(`INSERT INTO watch_lifecycle_preference(installation,receiver,epoch,incarnation,revision,enabled)
		VALUES ('home','watch',1,'old-pair',8,1)`).run();
	await db.prepare(`INSERT INTO watch_lifecycle_recovery(
		grant_id,installation,receiver,predecessor_epoch,predecessor,epoch,key_fingerprint,incarnation,operator_binding,restore_fence,expires_at)
		VALUES ('grant','home','watch',1,'old-pair',2,?,'new-pair','operator-fixture','restore-fixture',?)`).bind(fingerprint, now+30).run();

	const audience = "fixture-api";
	const common = { audience, installation:"home", receiver:"watch", epoch:2, incarnation:"new-pair", expiry:now+30, key_fingerprint:fingerprint };
	const claims = { ...common, action:"receiver-recover", operation:"recover", predecessor:"old-pair", predecessor_epoch:1, recovery_grant:"grant" };
	async function sign(value: object) {
		const body = new TextEncoder().encode(JSON.stringify(value));
		const frame = await frameLifecycleProof(body,audience,now);
		const signature = new Uint8Array(await crypto.subtle.sign({ name:"ECDSA",hash:"SHA-256" }, keys.privateKey, frame));
		return {body,signature};
	}
	const signed = await sign(claims);
	const authority = {assertCurrent() {}};
	const changed = new TextEncoder().encode(JSON.stringify({...claims,recovery_grant:"other"}));
	expect(await recoverWatchReceiver(db,changed,signed.signature,spki,audience,now,authority)).toBeNull();
	const wrong = await sign({...claims,predecessor:"wrong"});
	expect(await recoverWatchReceiver(db,wrong.body,wrong.signature,spki,audience,now,authority)).toBeNull();
	await expect(recoverWatchReceiver(db,signed.body,signed.signature,spki,audience,now,{assertCurrent() {
		throw new Error("restore fence denied");
	}})).rejects.toThrow("restore fence denied");
	expect(await db.prepare("SELECT consumed FROM watch_lifecycle_recovery").first("consumed")).toBe(0);
	const recover = () => recoverWatchReceiver(db,signed.body,signed.signature,spki,audience,now,authority);
	expect((await Promise.all([recover(),recover()])).filter(Boolean)).toEqual([
		{incarnation:"new-pair",epoch:2,operation:"recover"},
	]);
	expect(await db.prepare("SELECT epoch,incarnation,revision,enabled FROM watch_lifecycle_preference").first())
		.toEqual({epoch:2,incarnation:"new-pair",revision:0,enabled:0});
	const status = await sign({...common,action:"lifecycle-status",operation:"read",
		target_operation:"recover",target_body_sha256:hex(await crypto.subtle.digest("SHA-256",signed.body))});
	expect(await applyWatchPairing(db,status.body,status.signature,spki,audience,now))
		.toMatchObject({state:"committed_current",incarnation:"new-pair",operation:"recover",retired:0});
});
