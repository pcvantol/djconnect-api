import { resolveWatchRetirementScope } from "../src/watch-lifecycle/registry-scope";
import { env } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../src/watch-lifecycle/preference-schema.sql?raw";
import { applyWatchPairing } from "../src/watch-lifecycle/pairing";
import { createWatchRetirementHttp } from "../src/watch-lifecycle/retirement-http";
import { createWatchRetirement, type WatchRetirementPorts } from "../src/watch-lifecycle/retirement";
import { decodeLifecycleClaims } from "../src/watch-lifecycle/proof";
import { applyWatchPreference } from "../src/watch-lifecycle/preference";
import { frameLifecycleProof } from "../src/watch-lifecycle/proof";

it("blocks dispatch before retirement and keeps it blocked on D1 failure", async () => {
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
		return Object.assign(invoke, { bodyHash, body, signature });
	}

	const enroll = await signed("pair", "pair");
	expect(await enroll(applyWatchPairing)).toMatchObject({retired: 0});
	const retire = await signed("retire", "withdraw");
	const claims = decodeLifecycleClaims(retire.body, audience, now);
	const signal = new AbortController().signal;
	const status = await signed("lifecycle-status", "read-withdraw", {
		target_operation: claims.operation, target_body_sha256: retire.bodyHash,
	});
	const statusClaims = decodeLifecycleClaims(status.body, audience, now);
	const read = () => run(status.body, status.signature, statusClaims, signal);
	let blocked = false;
	let blockCalls = 0;
	let restoreCurrent = false;
	const mutable = { ...claims, receiver: "other-watch", incarnation: "other-pair" };
	let changeScopeDuringLookup = false;
	const ports: WatchRetirementPorts = {
		db, audience, now: () => now,
		async resolveEnrolledKey(scope) {
			if (changeScopeDuringLookup) {
				expect(Object.isFrozen(scope)).toBe(true);
				await Promise.resolve();
				Object.assign(mutable, {receiver: claims.receiver, incarnation: claims.incarnation});
			}
			return spki;
		},
		async isRestoreCurrent() { return restoreCurrent; },
		async blockDispatch(verified, bodyHash) {
			expect(verified).toEqual(claims);
			expect(bodyHash).toBe(retire.bodyHash);
			expect(await db.prepare("SELECT retired FROM watch_lifecycle_preference").first("retired")).toBe(0);
			blocked = true;
			blockCalls++;
			return true;
		},
		async hasDispatchBlock(verified, operation, hash) {
			expect(verified).toEqual(statusClaims);
			expect(operation).toBe(claims.operation);
			expect(hash).toBe(retire.bodyHash);
			return blocked;
		},
	};
	const run = createWatchRetirement(ports);
	expect(await run(retire.body, retire.signature, claims, signal)).toBe("denied");
	restoreCurrent = true;
	changeScopeDuringLookup = true;
	expect(await run(retire.body, retire.signature, mutable, signal)).toBe("denied");
	expect(mutable.receiver).toBe(claims.receiver);
	expect(blocked).toBe(false);
	changeScopeDuringLookup = false;
	expect(await run(retire.body, new Uint8Array(64), claims, signal)).toBe("denied");
	expect(blocked).toBe(false);
	await db.prepare("CREATE TRIGGER fixture_error BEFORE UPDATE ON watch_lifecycle_preference WHEN NEW.retired=1 BEGIN SELECT RAISE(ABORT, 'fixture error'); END").run();
	expect(await run(retire.body, retire.signature, claims, signal)).toBe("unknown");
	expect(blocked).toBe(true);
	expect(await read()).toBe("unknown");
	expect(await db.prepare("SELECT retired FROM watch_lifecycle_preference").first("retired")).toBe(0);
	await db.prepare("DROP TRIGGER fixture_error").run();
	expect(await run(retire.body, retire.signature, claims, signal)).toBe("committed");
	expect(await db.prepare("SELECT retired FROM watch_lifecycle_preference").first("retired")).toBe(1);
	expect(await read()).toBe("committed");
	blocked = false;
	expect(await read()).toBe("unknown");
	expect(blockCalls).toBe(2);

	expect(await resolveWatchRetirementScope(db, claims, signal)).toBeNull();
	expect(await resolveWatchRetirementScope(db, {...statusClaims, incarnation: "other-pair"}, signal)).toBeNull();
	expect(await resolveWatchRetirementScope(db, {...statusClaims, epoch: 2}, signal)).toBeNull();
	const handler = createWatchRetirementHttp(ports, (lookup, signal) => resolveWatchRetirementScope(db, lookup, signal));
	const request = (signature = status.signature) => new Request("https://fixture.invalid", {
		method: "POST", body: new Uint8Array(status.body), headers: {
			"content-type": "application/json",
			"djc-watch-lifecycle-signature": btoa(String.fromCharCode(...signature))
				.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
		},
	});
	expect((await handler(request(new Uint8Array(64)))).status).toBe(403);
	expect((await handler(request())).status).toBe(503);
	blocked = true;
	const confirmed = await handler(request());
	expect(confirmed.status).toBe(200);
	expect(await confirmed.json()).toEqual({outcome: "committed"});
	expect(blockCalls).toBe(2);

	await db.prepare("UPDATE watch_lifecycle_issuer SET active=0").run();
	expect((await handler(request())).status).toBe(403);

});
