import { env } from "cloudflare:test";
import { expect, it } from "vitest";
import schema from "../src/watch-lifecycle/preference-schema.sql?raw";
import { redeemWatchEnrollment } from "../src/watch-lifecycle/enrollment";

it("activates the exact approved issuer once, only after possession and current admission", async () => {
	const db = env.DB;
	for (const statement of schema.trim().split(/;\s*(?=CREATE)/)) await db.prepare(statement).run();
	const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
	const spki = await crypto.subtle.exportKey("spki", pair.publicKey);
	const hex = (bytes: ArrayBuffer) => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
	const fingerprint = hex(await crypto.subtle.digest("SHA-256", spki));
	const encode = (s: string) => new TextEncoder().encode(s);
	const expiry = Number(await db.prepare("SELECT unixepoch()").first("unixepoch()")) + 25;
	const nonce = "A".repeat(43);
	const nonceHash = hex(await crypto.subtle.digest("SHA-256", encode(nonce)));
	await db.prepare(`INSERT INTO watch_lifecycle_enrollment(
		challenge_id,audience,installation,operator_binding,restore_fence,nonce_hash,key_fingerprint,public_spki_hex,epoch,expires_at)
		VALUES ('c1','fixture-api','home','operator-fixture','restore-fixture',?,?,?,1,?)`)
		.bind(nonceHash, fingerprint, hex(spki), expiry).run();

	const pieces = ["DJC-WATCH-ENROLLMENT-V1\0"];
	for (const field of ["fixture-api", "home", fingerprint, "watch-lifecycle", "0", "1", nonce, String(expiry)]) {
		pieces.push(String.fromCharCode(0, 0, 0, field.length), field);
	}
	const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, encode(pieces.join(""))));
	const allow = { assertCurrent() {} };
	expect(await redeemWatchEnrollment(db, "c1", nonce, new Uint8Array(64), allow)).toBeNull();
	expect(await redeemWatchEnrollment(db, "c1", "B" + nonce.slice(1), signature, allow)).toBeNull();
	let checks = 0;
	await expect(redeemWatchEnrollment(db, "c1", nonce, signature, { assertCurrent() {
		if (++checks === 2) throw new Error("authority revoked");
	} })).rejects.toThrow("authority revoked");
	expect(await db.prepare("SELECT count(*) AS n FROM watch_lifecycle_issuer").first("n")).toBe(0);
	const receipts = await Promise.all([
		redeemWatchEnrollment(db, "c1", nonce, signature, allow),
		redeemWatchEnrollment(db, "c1", nonce, signature, allow),
	]);
	expect(receipts.filter(Boolean)).toEqual([{installation:"home",epoch:1,key_fingerprint:fingerprint,scope:"watch-lifecycle"}]);
	expect(await db.prepare("SELECT consumed FROM watch_lifecycle_enrollment").first("consumed")).toBe(1);
	expect(await db.prepare("SELECT epoch,active,public_spki_hex FROM watch_lifecycle_issuer").first())
		.toEqual({epoch:1,active:1,public_spki_hex:hex(spki)});
});
