import { expect, it } from "vitest";
import { frameLifecycleProof, verifyLifecycleProof } from "../src/watch-lifecycle/proof";

const audience = "api.djconnect.dev/watch-lifecycle/v1";
const now = 1900000000;
const bytes = (value: string) => new TextEncoder().encode(value);
const hex = (buffer: ArrayBuffer) => Array.from(new Uint8Array(buffer), b => b.toString(16).padStart(2, "0")).join("");
const vector = '{"audience":"api.djconnect.dev/watch-lifecycle/v1","action":"preference-write","installation":"fixture-install","receiver":"fixture-watch","epoch":7,"key_fingerprint":"abababababababababababababababababababababababababababababababab","incarnation":"fixture-pair","expiry":1900000030,"operation":"fixture-operation","expected_version":3,"enabled":false}';

it("matches the independent Core Python frame and rejects ambiguous input", async () => {
	const frame = await frameLifecycleProof(bytes(vector), audience, now);
	expect(hex(await crypto.subtle.digest("SHA-256", frame))).toBe("58faf0b4008a4c0cebf5e0aecc7fa6202f334e12c89a2bc8ce8373e0677d3327");
	for (const invalid of [vector.replace('"epoch":7', '"epoch":7,"epoch":7'), vector.replace('"enabled":false', '"enabled":false,"predecessor":null')]) {
		await expect(frameLifecycleProof(bytes(invalid), audience, now)).rejects.toThrow();
	}
	await expect(frameLifecycleProof(bytes(vector), audience, now + 30)).rejects.toThrow();
});

it("verifies exact signed bytes against the caller's expected public key", async () => {
	const pair = await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"}, true, ["sign","verify"]);
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki",pair.publicKey));
	const fingerprint = hex(await crypto.subtle.digest("SHA-256",spki));
	const body = vector.replace("ab".repeat(32), fingerprint);
	const original = bytes(body);
	const frame = await frameLifecycleProof(original, audience, now);
	const signature = new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"}, pair.privateKey, frame));
	expect(await verifyLifecycleProof(original,signature,spki,audience,now)).toMatchObject({enabled:false, expected_version:3});
	expect(await verifyLifecycleProof(bytes(body.replace('"enabled":false','"enabled":true')),signature,spki,audience,now)).toBeNull();
	expect(await verifyLifecycleProof(bytes(body.replace('{"audience"','{ "audience"')),signature,spki,audience,now)).toBeNull();
});
