import { env, SELF } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../../../src/watch-lifecycle/preference-schema.sql?raw";
import { frameLifecycleProof } from "../../../src/watch-lifecycle/proof";
import { applyWatchPairing } from "../../../src/watch-lifecycle/pairing";
import { watchRestoreActorName } from "../../../src/watch-lifecycle/dispatch-identity";
import type { WatchPrivatePreference } from "../../../src/watch-lifecycle/private-entrypoint";
import type { PreferenceActor, PrivatePreference } from "./worker";

it("runs signed preference ordering and expiry through a named Worker binding and owning DO", async () => {
	const { DB, PREFERENCE, ROUTED, ACTOR } = env as unknown as {
		DB: D1Database; PREFERENCE: Service<PrivatePreference>; ROUTED: Service<WatchPrivatePreference>; ACTOR: DurableObjectNamespace<PreferenceActor>;
	};
	for (const sql of schema.trim().split(/;\s*(?=CREATE)/)) await DB.prepare(sql).run();
	const actor = ACTOR.getByName("fixture-home:fixture-watch");
	const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
	const hex = (bytes: Uint8Array) => Array.from(bytes, x => x.toString(16).padStart(2, "0")).join("");
	const fingerprint = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", spki)));
	const scope = { installation: "home", receiver: "watch", incarnation: "pair-a", epoch: 1, key_fingerprint: fingerprint };
	await DB.prepare("INSERT INTO watch_lifecycle_issuer(installation,epoch,key_fingerprint,scope,active,public_spki_hex) VALUES ('home',1,?,'watch-lifecycle',1,?)")
		.bind(fingerprint, hex(spki)).run();
	const now = Math.floor(Date.now() / 1000);
	const expiresAt = now + 25;
	async function sign(action: string, operation: string, extra = {}) {
		const body = new TextEncoder().encode(JSON.stringify({ ...scope, audience: "lab", action, operation, expiry: expiresAt, ...extra }));
		const bytes = await frameLifecycleProof(body, "lab", now);
		const proof = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, bytes));
		return { body, proof };
	}
	const pairing = await sign("pair", "pair");
	expect(await applyWatchPairing(DB, pairing.body, pairing.proof, spki, "lab", now, () => {})).not.toBeNull();
	expect((await SELF.fetch("https://fixture.invalid/watch-preference")).status).toBe(404);

	const old = await sign("preference-write", "old-on", { expected_version: 0, enabled: true });
	const latest = await sign("preference-write", "new-off", { expected_version: 0, enabled: false });
	const context = () => ({
		action: "preference-write" as const, expiresAt, submitBeforeMs: Date.now() + 3000,
		installation: "home", credentialId: "fixture-machine", credentialGeneration: 1,
	});
	const send = (signed: Awaited<ReturnType<typeof sign>>, overrides = {}) =>
		PREFERENCE.preference({ ...context(), ...overrides }, signed.body, signed.proof);
	expect((await send(old)).status).toBe(403);
	const fixtureAdmission = { ...scope, credentialId: "fixture-machine", credentialGeneration: 1 };
	await actor.admit(fixtureAdmission);
	const ownerName = await watchRestoreActorName(scope);
	expect(ownerName).not.toBeNull();
	const owner = ACTOR.getByName(ownerName!);
	const read = await sign("preference-read", "status");
	const readContext = { ...context(), action: "preference-read" as const };
	expect((await ROUTED.preference(readContext, read.body, read.proof)).status).toBe(403);
	await owner.admit(fixtureAdmission);
	const wrongReceiver = await sign("preference-read", "other-status", { receiver: "other-watch" });
	expect((await ROUTED.preference(readContext, wrongReceiver.body, wrongReceiver.proof)).status).toBe(403);
	const routed = await ROUTED.preference(readContext, read.body, read.proof);
	expect(routed.status).toBe(200);
	expect(await routed.json()).toMatchObject({ revision: 0, enabled: 0 });
	expect((await send(old, { credentialGeneration: 2 })).status).toBe(403);
	const delayed = send(old, { pauseBeforeBatch: true });
	try {
		await expect.poll(async () => (await actor.status()).paused).toBe(true);
		const applied = await send(latest);
		expect(applied.status).toBe(200);
		expect(await applied.json()).toMatchObject({ revision: 1, enabled: 0, operation: "new-off" });
	} finally {
		await actor.resume();
	}
	expect((await delayed).status).toBe(403);
	expect((await send(old)).status).toBe(403);

	const expiresWhilePaused = await sign("preference-write", "expired-on", { expected_version: 1, enabled: true });
	const submitBeforeMs = Date.now() + 2000;
	const expiring = send(expiresWhilePaused, { submitBeforeMs, pauseBeforeLookup: true });
	try {
		await expect.poll(async () => (await actor.status()).paused).toBe(true);
		await new Promise(resolve => setTimeout(resolve, Math.max(0, submitBeforeMs - Date.now()) + 30));
	} finally {
		await actor.resume();
	}
	expect((await expiring).status).toBe(403);
	const revoking = send(expiresWhilePaused, { pauseBeforeLookup: true });
	try {
		await expect.poll(async () => (await actor.status()).paused).toBe(true);
		await actor.revoke();
	} finally {
		await actor.resume();
	}
	expect((await revoking).status).toBe(403);
	expect((await actor.status()).batches).toBe(3);
	expect(await DB.prepare("SELECT revision, enabled, operation FROM watch_lifecycle_preference").first())
		.toEqual({ revision: 1, enabled: 0, operation: "new-off" });
}, 10000);
