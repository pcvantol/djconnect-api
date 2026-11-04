import { expect, it } from "vitest";
import { createWatchAccessIngress } from "../src/watch-lifecycle/access-ingress";

const encoder = new TextEncoder();
const base64url = (bytes: Uint8Array) =>
	btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const segment = (value: object) => base64url(encoder.encode(JSON.stringify(value)));

it("forwards only original proof bytes and server admission from verified HA Access ingress", async () => {
	const now = Math.floor(Date.now() / 1000);
	const endpoint = "https://fixture.invalid/watch-preference";
	const issuer = "https://fixture.cloudflareaccess.com";
	const pair = await crypto.subtle.generateKey({
		name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
	}, false, ["sign", "verify"]);
	const claims = {
		iss: issuer, aud: ["watch-access"], common_name: "machine.access", type: "app", sub: "", iat: now - 1, exp: now + 60,
	};
	async function token(overrides: object = {}) {
		const input = segment({ alg: "RS256", kid: "fixture-key" }) + "." + segment({ ...claims, ...overrides });
		const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, encoder.encode(input));
		return input + "." + base64url(new Uint8Array(signature));
	}
	const operation = {
		audience: "watch-lifecycle", installation: "home", receiver: "watch", incarnation: "pair-a", epoch: 1,
		key_fingerprint: "a".repeat(64), operation: "read", action: "preference-read", expiry: now + 20,
	};
	const rawBody = JSON.stringify(operation, null, 1);
	const proof = new Uint8Array(64).fill(5);
	const request = (assertion: string, url = endpoint, body = rawBody, headers = {}) => new Request(url, {
		method: "POST", body, headers: {
			"content-type": "application/json", "cf-access-jwt-assertion": assertion,
			"djc-watch-lifecycle-signature": base64url(proof), "cf-access-client-id": "untrusted-header", ...headers,
		},
	});
	const access = { access: {} as CloudflareAccessContext };
	let calls = 0;
	const ingress = createWatchAccessIngress({
		endpoint, issuer, accessAudience: "watch-access", lifecycleAudience: "watch-lifecycle",
		installation: "home", credentialId: "machine.access", credentialGeneration: 3, maxAssertionAgeSeconds: 20,
		async resolveVerificationKey(kid) { return kid === "fixture-key" ? pair.publicKey : null; },
	}, {
		async preference(context, body, signature) {
			calls++;
			expect(context).toEqual({
				installation: "home", credentialId: "machine.access", credentialGeneration: 3,
				action: "preference-read", expiresAt: now + 19,
			});
			expect(new TextDecoder().decode(body)).toBe(rawBody);
			expect(signature).toEqual(proof);
			return new Response(null, { status: 204 });
		},
	});
	const valid = await token();
	expect((await createWatchAccessIngress()(request(valid), access)).status).toBe(403);
	expect((await ingress(request(valid), {})).status).toBe(403);
	expect((await ingress(request(valid, "https://preview.invalid/watch-preference"), access)).status).toBe(403);
	expect((await ingress(request(valid, endpoint, rawBody, { cookie: "CF_Authorization=old" }), access)).status).toBe(403);
	for (const mismatch of [{ aud: ["elsewhere"] }, { common_name: "other.access" }, { iss: "https://elsewhere.invalid" },
		{ sub: "user" }, { iat: now - 30 }, { exp: now - 1 }]) {
		expect((await ingress(request(await token(mismatch)), access)).status).toBe(403);
	}
	const [header, , signature] = valid.split(".");
	const forged = [header, segment({ ...claims, exp: now + 100 }), signature].join(".");
	expect((await ingress(request(forged), access)).status).toBe(403);
	expect((await ingress(request(valid, endpoint, JSON.stringify({ ...operation, installation: "other" })), access)).status).toBe(403);
	expect(calls).toBe(0);
	expect((await ingress(request(valid), access)).status).toBe(204);
	expect(calls).toBe(1);
});
