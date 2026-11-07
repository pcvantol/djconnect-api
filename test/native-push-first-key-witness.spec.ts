import { expect, it } from "vitest";
import vector from "../qualification/native-push-mvp/first-key-witness-vector.json";
import statusVector from "../qualification/native-push-mvp/first-key-status-vector.json";
import {
	firstKeyRegisterBytes, firstKeyStatusBytes, type FirstKeyChallenge, type FirstKeyStatusChallenge,
} from "../qualification/native-push-mvp/first-key-witness";

const challenge = vector.challengeResponse as FirstKeyChallenge;
const decode = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const decodeSignature = (value: string) => decode(value.replace(/-/g, "+").replace(/_/g, "/") + "==");
const spki = decode(vector.register.core_public_key_spki_b64);
const signature = decodeSignature(vector.register.core_signature_b64url);
const sha256 = async (bytes: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

async function verify(bytes: Uint8Array<ArrayBuffer>, proof = signature, publicKey = spki) {
	const key = await crypto.subtle.importKey("spki", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, proof, bytes);
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

it("verifies the status read under the original key and keeps register and status signatures separate", async () => {
	const original = firstKeyRegisterBytes(statusVector.registerChallenge as FirstKeyChallenge, statusVector.binding);
	const status = statusVector.statusChallenge as FirstKeyStatusChallenge;
	const readback = firstKeyStatusBytes(status);
	const key = decode(statusVector.core_public_key_spki_b64);
	const registerProof = decodeSignature(statusVector.registerSignatureB64url);
	const statusProof = decodeSignature(statusVector.statusSignatureB64url);
	expect(hex(await sha256(original))).toBe(status.transcript_sha256);
	expect(hex(await sha256(key))).toBe(status.core_key_thumbprint);
	expect(new TextDecoder().decode(readback)).toBe(statusVector.statusCanonicalUtf8);
	expect(hex(await sha256(readback))).toBe(statusVector.statusSha256);
	expect(await verify(original, registerProof, key)).toBe(true);
	expect(await verify(readback, statusProof, key)).toBe(true);
	expect(await verify(original, statusProof, key)).toBe(false);
	expect(await verify(readback, registerProof, key)).toBe(false);
	expect(await verify(readback, statusProof, spki)).toBe(false);
});

it("binds the readback to the original operation and caps the fresh nonce at the original deadline", async () => {
	const status = statusVector.statusChallenge as FirstKeyStatusChallenge;
	const key = decode(statusVector.core_public_key_spki_b64);
	const proof = decodeSignature(statusVector.statusSignatureB64url);
	for (const mutation of [
		{ operation_id: "other-operation" }, { install_credential_id: "new-credential" },
		{ api_installation_id: "other-installation" }, { pairing_generation: "retired-pairing" },
		{ transcript_sha256: "1".repeat(64) }, { expires_at_ms: status.expires_at_ms + 1 },
		{ status_nonce_id: "other-status-nonce" }, { status_nonce: "A".repeat(43) },
		{ status_nonce_expires_at_ms: status.status_nonce_expires_at_ms + 1 },
	]) expect(await verify(firstKeyStatusBytes({ ...status, ...mutation }), proof, key)).toBe(false);
	expect(() => firstKeyStatusBytes({ ...status, status_nonce_expires_at_ms: status.expires_at_ms + 1 }))
		.toThrow(TypeError);
});
