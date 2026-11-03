import { env } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../src/watch-lifecycle/preference-schema.sql?raw";
import { applyWatchPairing } from "../src/watch-lifecycle/pairing";
import { applyWatchPreference } from "../src/watch-lifecycle/preference";
import { frameLifecycleProof } from "../src/watch-lifecycle/proof";

it("stores only the current signed preference and keeps opt-out available at capacity", async () => {
	const db = env.DB;
	for (const statement of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(statement).run();
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
	const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)),
		b => b.toString(16).padStart(2, "0")).join("");
	await db.prepare("INSERT INTO watch_lifecycle_issuer VALUES ('home',1,?,'watch-lifecycle',1)").bind(fingerprint).run();
	const now = Number(await db.prepare("SELECT unixepoch()").first("unixepoch()"));
	const audience = "test-api";
	async function signed(action: string, operation: string, extra: object = {}) {
		const body = new TextEncoder().encode(JSON.stringify({
			audience, action, operation, installation: "home", receiver: "watch", incarnation: "pair-a",
			epoch: 1, key_fingerprint: fingerprint, expiry: now + 30, ...extra,
		}));
		const bytes = await frameLifecycleProof(body, audience, now);
		const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, bytes));
		return (apply: typeof applyWatchPreference | typeof applyWatchPairing = applyWatchPreference) =>
			apply(db, body, signature, spki, audience, now);
	}
	const enroll = await signed("pair", "pair");
	expect(await enroll(applyWatchPairing)).toMatchObject({ incarnation: "pair-a", enabled: 0, retired: 0 });
	expect(await enroll(applyWatchPairing)).toBeNull();
	const optIn = await signed("preference-write", "on", { expected_version: 0, enabled: true });
	expect(await optIn()).toMatchObject({ revision: 1, operation: "on", enabled: 1 });
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
	const restoreOld = await signed("replace", "restore-old", { predecessor: "pair-b" });
	expect(await restoreOld(applyWatchPairing)).toBeNull();
	expect(await read()).toBeNull();
	const retire = await signed("retire", "retire", { incarnation: "pair-b" });
	expect(await retire(applyWatchPairing)).toMatchObject({ incarnation: "pair-b", enabled: 0, retired: 1 });
	const readRetired = await signed("preference-read", "read-retired", { incarnation: "pair-b" });
	expect(await readRetired()).toBeNull();
	await db.prepare("UPDATE watch_lifecycle_issuer SET active=0 WHERE installation='home'").run();
	expect(await read()).toBeNull();
	expect(await optOut()).toBeNull();
});
