import { expect, it } from "vitest";
import vector from "../qualification/native-push-mvp/first-key-witness-vector.json";
import {
	firstKeyRegisterBytes, type FirstKeyChallenge,
} from "../qualification/native-push-mvp/first-key-witness";

const challenge = vector.challengeResponse as FirstKeyChallenge;
const decode = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const spki = decode(vector.register.core_public_key_spki_b64);
const signature = decode(vector.register.core_signature_b64url.replace(/-/g, "+").replace(/_/g, "/") + "==");
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

async function verify(bytes: Uint8Array<ArrayBuffer>) {
	const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, bytes);
}

it("reconstructs the common Core and Apple first-key transcript from the original challenge and pairing binding", async () => {
	const bytes = firstKeyRegisterBytes(challenge, vector.challengeRequest);
	expect(new TextDecoder().decode(bytes)).toBe(vector.canonicalUtf8);
	expect(hex(await sha256(spki))).toBe(vector.challengeRequest.core_key_thumbprint);
	const digest = await sha256(bytes);
	expect(hex(digest)).toBe(vector.transcriptSha256);
	expect(digest).toEqual(decode(vector.appleClientDataHashB64));
	expect(await verify(bytes)).toBe(true);
});

it("rejects a captured Core signature after changing the API reservation, credential, nonce or original deadline", async () => {
	for (const mutation of [
		{ api_installation_id: "other-install" }, { install_credential_id: "rotated-credential" },
		{ operation_id: "other-operation" }, { challenge_id: "other-challenge" },
		{ challenge_nonce: "A".repeat(43) }, { expires_at_ms: challenge.expires_at_ms + 1 },
	]) expect(await verify(firstKeyRegisterBytes({ ...challenge, ...mutation }, vector.challengeRequest))).toBe(false);
});

it("rejects reuse for another pairing, owner, device, key or operation domain", async () => {
	for (const mutation of [
		{ pairing_generation: "different-generation" }, { pair_binding: "1".repeat(64) },
		{ owner_binding: "2".repeat(64) }, { device_binding: "3".repeat(64) },
		{ core_key_thumbprint: "4".repeat(64) },
	]) expect(await verify(firstKeyRegisterBytes(challenge, { ...vector.challengeRequest, ...mutation }))).toBe(false);
	const wrongDomain = vector.canonicalUtf8.replace("/key/register", "/key/status");
	expect(await verify(new TextEncoder().encode(wrongDomain))).toBe(false);
});

it("requires a canonical nonce and the first-key revision zero", () => {
	expect(() => firstKeyRegisterBytes({ ...challenge, challenge_nonce: "A".repeat(42) + "B" }, vector.challengeRequest))
		.toThrow(TypeError);
	expect(() => firstKeyRegisterBytes({ ...challenge, expected_key_revision: 1 as 0 }, vector.challengeRequest))
		.toThrow(TypeError);
});
