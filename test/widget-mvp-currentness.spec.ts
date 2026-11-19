import { expect, it } from "vitest";
import vector from "../qualification/native-push-mvp/widget-currentness-vector.json";
import { widgetCurrentnessBytes } from "../qualification/native-push-mvp/widget-currentness";

const decode = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const spki = decode(vector.publicKeySpkiB64);
const signature = decode(vector.signatureB64url.replace(/-/g, "+").replace(/_/g, "/") + "==");
const sha256 = async (value: Uint8Array<ArrayBuffer>) =>
	Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", value)), byte => byte.toString(16).padStart(2, "0")).join("");
const verify = async (statement: Uint8Array<ArrayBuffer>) => {
	const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, statement);
};

it("verifies the exact cross-repository WidgetKit currentness vector in Workerd", async () => {
	const statement = widgetCurrentnessBytes(vector.scope);
	expect(new TextDecoder().decode(statement)).toBe(vector.canonicalUtf8);
	expect(await sha256(statement)).toBe(vector.canonicalSha256);
	expect(await sha256(spki)).toBe(vector.scope.coreKeyThumbprint);
	expect(await verify(statement)).toBe(true);
});

it("rejects reuse for a different credential, key revision, device, target, consent, deadline or operation", async () => {
	for (const mutation of [
		{ installCredentialId: "other-credential" }, { keyRevision: 2 }, { coreKeyThumbprint: "1".repeat(64) },
		{ deviceBinding: "2".repeat(64) }, { targetDigest: "3".repeat(64) }, { consentGeneration: "other-consent" },
		{ deadlineMs: vector.scope.deadlineMs + 1 }, { operationId: "other-operation" },
		{ nonce: "A".repeat(43) }, { requestDigest: "4".repeat(64) }, { registrationId: "other-registration" },
	]) expect(await verify(widgetCurrentnessBytes({ ...vector.scope, ...mutation }))).toBe(false);
	// The same proof is never a send permit or a proof for another channel.
	for (const [before, after] of [
		["/enrollment/issue", "/event"], ['"widget","widget"', '"live_activity","live_activity_start"'],
		['"opt_in"', '"opt_out"'],
	]) expect(await verify(new TextEncoder().encode(vector.canonicalUtf8.replace(before, after)))).toBe(false);
});

it("rejects ambiguous nonce encodings, non-opaque identifiers and non-integer deadlines", () => {
	for (const mutation of [{ nonce: "A".repeat(42) + "B" }, { operationId: "invalid/id" }, { deadlineMs: 1.5 }]) {
		expect(() => widgetCurrentnessBytes({ ...vector.scope, ...mutation })).toThrow(TypeError);
	}
});
