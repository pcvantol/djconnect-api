import { env } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../src/watch-lifecycle/preference-schema.sql?raw";
import { applyWatchPairing } from "../src/watch-lifecycle/pairing";
import { createWatchPreferenceHttp } from "../src/watch-lifecycle/preference-http";
import { applyWatchPreference } from "../src/watch-lifecycle/preference";
import { frameLifecycleProof } from "../src/watch-lifecycle/proof";

it("stores only the current signed preference and keeps opt-out available at capacity", async () => {
	const db = env.DB;
	for (const statement of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(statement).run();
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
	const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)),
		b => b.toString(16).padStart(2, "0")).join("");
	await db.prepare("INSERT INTO watch_lifecycle_issuer(installation,epoch,key_fingerprint,scope,active,public_spki_hex) VALUES ('home',1,?,'watch-lifecycle',1,?)").bind(fingerprint, Array.from(spki,b=>b.toString(16).padStart(2,"0")).join("")).run();
	const now = Number(await db.prepare("SELECT unixepoch()").first("unixepoch()"));
	const audience = "test-api";
	async function signed(action: string, operation: string, extra: object = {}) {
		const body = new TextEncoder().encode(JSON.stringify({
			audience, action, operation, installation: "home", receiver: "watch", incarnation: "pair-a",
			epoch: 1, key_fingerprint: fingerprint, expiry: now + 30, ...extra,
		}));
		const bytes = await frameLifecycleProof(body, audience, now);
		const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, bytes));
		const bodyHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)),
			b => b.toString(16).padStart(2, "0")).join("");
		const invoke = (apply: typeof applyWatchPreference | typeof applyWatchPairing = applyWatchPreference) =>
			apply(db, body, signature, spki, audience, now, () => {});
		const request = () => new Request("https://fixture.invalid", {
			method: "POST", body, headers: { "content-type": "application/json",
				"djc-watch-lifecycle-signature": btoa(String.fromCharCode(...signature))
					.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") },
		});
		return Object.assign(invoke, { bodyHash, request });
	}
	const enroll = await signed("pair", "pair");
	expect(await enroll(applyWatchPairing)).toMatchObject({ incarnation: "pair-a", enabled: 0, retired: 0 });
	expect(await enroll(applyWatchPairing)).toBeNull();
	const pairStatus = await signed("lifecycle-status", "check-pair", {
		target_operation: "pair", target_body_sha256: enroll.bodyHash,
	});
	expect(await pairStatus(applyWatchPairing)).toEqual({
		state: "committed_current", incarnation: "pair-a", revision: 1,
		operation: "pair", body_hash: enroll.bodyHash, retired: 0,
	});
	const wrongDigest = await signed("lifecycle-status", "check-wrong", {
		target_operation: "pair", target_body_sha256: "0".repeat(64),
	});
	expect(await wrongDigest(applyWatchPairing)).toBeNull();
	const optIn = await signed("preference-write", "on", { expected_version: 0, enabled: true });
	const deny = createWatchPreferenceHttp(db, audience, () => { throw new Error("private restore denial"); });
	const rejected = await deny(optIn.request());
	expect(rejected.status).toBe(403);
	expect(await rejected.json()).toEqual({error:"watch_preference_unavailable"});
	expect(await db.prepare("SELECT revision FROM watch_lifecycle_preference").first("revision")).toBe(0);
	const http = createWatchPreferenceHttp(db, audience, () => {});
	const response = await http(optIn.request());
	expect(response.status).toBe(200);
	expect(response.headers.get("cache-control")).toBe("no-store");
	expect(await response.json()).toMatchObject({ revision: 1, operation: "on", enabled: 1 });
	const unsigned = optIn.request();
	unsigned.headers.delete("djc-watch-lifecycle-signature");
	expect((await http(unsigned)).status).toBe(403);
	expect(await optIn()).toMatchObject({ revision: 1, operation: "on", enabled: 1 });
	await db.prepare(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4095)
		INSERT INTO watch_lifecycle_intent SELECT 'home','watch',1,'pair-a','seed-'||x,'fixture' FROM n`).run();
	const optOut = await signed("preference-write", "off", { expected_version: 1, enabled: false });
	expect(await optOut()).toMatchObject({ revision: 2, operation: "off", enabled: 0, sealed: 1 });
	expect(await optIn()).toBeNull();
	expect(await optOut()).toBeNull();
	const read = await signed("preference-read", "read");
	expect(await read()).toMatchObject({ revision: 2, operation: "off", enabled: 0 });
	const replace = await signed("replace", "replace", { incarnation: "pair-b", predecessor: "pair-a" });
	expect(await replace(applyWatchPairing)).toMatchObject({ incarnation: "pair-b", revision: 0, enabled: 0 });
	expect(await pairStatus(applyWatchPairing)).toEqual({ state: "superseded" });
	const replaceStatus = await signed("lifecycle-status", "check-replace", {
		incarnation: "pair-b", target_operation: "replace", target_body_sha256: replace.bodyHash,
	});
	expect(await replaceStatus(applyWatchPairing)).toMatchObject({ state: "committed_current", revision: 2 });
	const restoreOld = await signed("replace", "restore-old", { predecessor: "pair-b" });
	expect(await restoreOld(applyWatchPairing)).toBeNull();
	expect(await read()).toBeNull();
	await db.prepare(`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<4094)
		INSERT INTO watch_lifecycle_incarnation SELECT 'home','watch','seed-incarnation-'||x FROM n`).run();
	const overCapacity = await signed("replace", "over-capacity", { incarnation: "pair-d", predecessor: "pair-b" });
	expect(await overCapacity(applyWatchPairing)).toBeNull();
	const delayedReplace = await signed("replace", "delayed-replace", { incarnation: "pair-c", predecessor: "pair-b" });
	const retire = await signed("retire", "retire", { incarnation: "pair-b" });
	expect(await retire(applyWatchPairing)).toMatchObject({ incarnation: "pair-b", enabled: 0, retired: 1 });
	expect(await db.prepare("SELECT count(*) AS n FROM watch_lifecycle_incarnation").first("n")).toBe(4096);
	await db.prepare("DELETE FROM watch_lifecycle_incarnation WHERE incarnation LIKE 'seed-incarnation-%'").run();
	expect(await delayedReplace(applyWatchPairing)).toBeNull();
	expect(await db.prepare("SELECT incarnation,retired FROM watch_lifecycle_preference").first())
		.toEqual({ incarnation: "pair-b", retired: 1 });
	const lateOptIn = await signed("preference-write", "late-on", {
		incarnation: "pair-c", expected_version: 0, enabled: true,
	});
	expect(await lateOptIn()).toBeNull();
	expect(await replaceStatus(applyWatchPairing)).toEqual({ state: "superseded" });
	const retireStatus = await signed("lifecycle-status", "check-retire", {
		incarnation: "pair-b", target_operation: "retire", target_body_sha256: retire.bodyHash,
	});
	expect(await retireStatus(applyWatchPairing)).toMatchObject({ state: "committed_current", revision: 3, retired: 1 });
	const unknown = await signed("lifecycle-status", "check-unknown", {
		target_operation: "never-committed", target_body_sha256: "0".repeat(64),
	});
	expect(await unknown(applyWatchPairing)).toEqual({ state: "unknown" });
	const readRetired = await signed("preference-read", "read-retired", { incarnation: "pair-b" });
	expect(await readRetired()).toBeNull();
	await db.prepare("UPDATE watch_lifecycle_issuer SET active=0 WHERE installation='home'").run();
	expect(await read()).toBeNull();
	expect(await optOut()).toBeNull();
	expect(await retireStatus(applyWatchPairing)).toBeNull();
});
