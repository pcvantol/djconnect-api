import { createWatchEnrollmentIssueHttp, createWatchEnrollmentRedeemHttp } from "../src/watch-lifecycle/enrollment-http";
import { env } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../src/watch-lifecycle/preference-schema.sql?raw";
import { issueWatchEnrollmentChallenge, redeemWatchEnrollment } from "../src/watch-lifecycle/enrollment";

it("activates the exact approved issuer once, only after possession and current admission", async () => {
	const db = env.DB;
	for (const statement of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(statement).run();
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
	const hex = (bytes: ArrayBuffer) => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
	const fingerprint = hex(await crypto.subtle.digest("SHA-256", spki));
	const encode = (s: string) => new TextEncoder().encode(s);
	const expiry = Number(await db.prepare("SELECT unixepoch()").first("unixepoch()")) + 25;
	const intent = {
		audience:"fixture-api", installation:"home", operator_binding:"a".repeat(64),
		restore_fence:"b".repeat(64), key_fingerprint:fingerprint, expected_epoch:0, expiry,
	};
	const request = () => new Request("https://fixture.invalid", {
		method: "POST", body: JSON.stringify({installation:"untrusted-body", expected_epoch:5}),
	});
	expect((await createWatchEnrollmentIssueHttp(db)(request())).status).toBe(403);
	expect((await createWatchEnrollmentIssueHttp(db, async () => null)(request())).status).toBe(403);
	const mismatch = createWatchEnrollmentIssueHttp(db, async () => ({
		intent: {...intent, key_fingerprint:"f".repeat(64)}, publicSpki:new Uint8Array(spki), assertCurrent() {},
	}));
	expect((await mismatch(request())).status).toBe(403);
	const issue = createWatchEnrollmentIssueHttp(db, async () => ({
		intent, publicSpki:new Uint8Array(spki), assertCurrent(value) {
			expect(value).toEqual(intent);
		},
	}));
	await expect(issueWatchEnrollmentChallenge(db,intent,new Uint8Array(spki),() => {
		throw new Error("operator denied");
	})).rejects.toThrow("operator denied");
	expect(await db.prepare("SELECT count(*) AS n FROM watch_lifecycle_enrollment").first("n")).toBe(0);
	const issued = await Promise.all([issue(request()),issue(request())]);
	expect(issued.map(reply => reply.status).sort()).toEqual([201,403]);
	const { nonce, challenge_id: challengeId, installation, expected_epoch } =
		await issued.find(reply => reply.status === 201)!.json<{nonce:string;challenge_id:string;installation:string;expected_epoch:number}>();
	expect(installation).toBe("home");
	expect(expected_epoch).toBe(0);
	expect(nonce).toHaveLength(43);
	expect(await db.prepare("SELECT nonce_hash FROM watch_lifecycle_enrollment").first("nonce_hash"))
		.toBe(hex(await crypto.subtle.digest("SHA-256",encode(nonce))));

	const pieces = ["DJC-WATCH-ENROLLMENT-V1\0"];
	for (const field of ["fixture-api", "home", fingerprint, "watch-lifecycle", "0", "1", nonce, String(expiry)]) {
		pieces.push(String.fromCharCode(0, 0, 0, field.length), field);
	}
	const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, encode(pieces.join(""))));
	const allow = { assertCurrent() {} };
	expect(await redeemWatchEnrollment(db, challengeId, nonce, new Uint8Array(64), allow)).toBeNull();
	expect(await redeemWatchEnrollment(db, challengeId, (nonce.startsWith("A") ? "B" : "A") + nonce.slice(1), signature, allow)).toBeNull();
	let checks = 0;
	await expect(redeemWatchEnrollment(db, challengeId, nonce, signature, { assertCurrent() {
		if (++checks === 2) throw new Error("authority revoked");
	} })).rejects.toThrow("authority revoked");
	expect(await db.prepare("SELECT count(*) AS n FROM watch_lifecycle_issuer").first("n")).toBe(0);
	const redeemRequest = () => new Request("https://fixture.invalid", {
		method:"POST", body:JSON.stringify({challenge_id:challengeId,nonce}),
		headers:{"content-type":"application/json","djc-watch-lifecycle-signature":btoa(String.fromCharCode(...signature))
			.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")},
	});
	expect((await createWatchEnrollmentRedeemHttp(db)(redeemRequest())).status).toBe(403);
	let restoreChecks = 0;
	const revoked = createWatchEnrollmentRedeemHttp(db, {assertCurrent() {
		if (++restoreChecks === 2) throw new Error("authority revoked before commit");
	}});
	expect((await revoked(redeemRequest())).status).toBe(403);
	expect(restoreChecks).toBe(2);
	expect(await db.prepare("SELECT count(*) AS n FROM watch_lifecycle_issuer").first("n")).toBe(0);
	const redeem = createWatchEnrollmentRedeemHttp(db, allow);
	const receipts = await Promise.all([redeem(redeemRequest()),redeem(redeemRequest())]);
	expect(receipts.map(reply => reply.status).sort()).toEqual([200,403]);
	expect(await receipts.find(reply => reply.status === 200)!.json())
		.toEqual({installation:"home",epoch:1,key_fingerprint:fingerprint,scope:"watch-lifecycle"});
	expect(await db.prepare("SELECT consumed FROM watch_lifecycle_enrollment").first("consumed")).toBe(1);
	expect(await db.prepare("SELECT epoch,active,public_spki_hex FROM watch_lifecycle_issuer").first())
		.toEqual({epoch:1,active:1,public_spki_hex:hex(spki)});
});
