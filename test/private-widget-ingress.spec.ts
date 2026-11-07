import { env } from "cloudflare:test";
import { beforeAll, expect, it, vi } from "vitest";
import baseMigration from "../migrations/0009_surface_push.sql?raw";
import issuerMigration from "../migrations/0010_surface_delegations.sql?raw";
import enrollmentMigration from "../migrations/0011_surface_enrollment_authorizations.sql?raw";
import { base64Url } from "../src/crypto";
import { createSurfaceEnrollment } from "../src/surface-push/enrollment";
import { redemptionBytes, type Authorization, type Redemption } from "../src/surface-push/enrollment-wire";
import { signingBytes, thumbprint, type Statement } from "../src/surface-push/issuer-wire";
import { createPrivateWidgetIngress } from "../src/surface-push/private-widget-ingress";
import * as composition from "../src/surface-push/composition";
import type { AppEnv } from "../src/types";

const origin = "https://widget-ha-dev.fixture.invalid";
const prefix = "/v1/push/surface/";
const issuer = "https://fixture.cloudflareaccess.com";
const audience = "widget-fixture-audience";
const clientId = "widget-fixture.access";
const now = Date.now();
const seconds = Math.floor(now / 1000);
const expiry = now + 120_000;
const operator = "fixture-private-widget-operator";
const context = { access: {} } as Pick<ExecutionContext, "access">;
const signing = { name: "ECDSA", hash: "SHA-256" };
let sequence = 0;
let accessKey: CryptoKeyPair;
let purposeKey: CryptoKeyPair;
let jwk: Authorization["enrollment"]["public_key"];

beforeAll(async () => {
	for (const sql of [baseMigration, issuerMigration, enrollmentMigration].join("\n").split(";")) {
		if (sql.replace(/--[^\n]*/g, "").trim()) await env.DB.prepare(sql).run();
	}
	[accessKey, purposeKey] = await Promise.all([
		crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]),
		crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]),
	]);
	const { x, y } = await crypto.subtle.exportKey("jwk", purposeKey.publicKey);
	jwk = { kty: "EC", crv: "P-256", x: x!, y: y! };
});

function operation() {
	return now.toString(16).padStart(12, "0").replace(/^(.{8})(.{4})$/, "$1-$2") +
		"-7000-8000-" + (++sequence).toString(16).padStart(12, "0");
}
async function jwt(overrides: Record<string, unknown> = {}) {
	const header = base64Url(JSON.stringify({ alg: "RS256", kid: "widget-test-key" }));
	const payload = base64Url(JSON.stringify({ iss: issuer, aud: [audience], common_name: clientId,
		type: "app", sub: "", exp: seconds + 60, iat: seconds - 1, ...overrides }));
	const bytes = new TextEncoder().encode(header + "." + payload);
	const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", accessKey.privateKey, bytes);
	return header + "." + payload + "." + base64Url(signature);
}
function request(path: string, body: unknown, assertion: string, authorization?: string) {
	return new Request(origin + prefix + path, {
		method: "POST", body: JSON.stringify(body), headers: {
			"content-type": "application/json", "cf-access-jwt-assertion": assertion,
			"cf-access-client-id": clientId, "cf-access-client-secret": "fixture-access-secret",
			...(authorization ? { authorization } : {}),
		},
	});
}
function configuration() {
	return {
		env: { DB: env.DB, DJCONNECT_RELAY_SECRET: operator,
			APNS_TOKEN_ENCRYPTION_KEY: btoa("0123456789abcdef0123456789abcdef") } as AppEnv,
		origin, issuer, audience, clientId, credentialGeneration: 4,
		maxAssertionAgeSeconds: 30, isCredentialCurrent: (generation: number) => generation === 4,
		now: () => now, resolveVerificationKey: async () => accessKey.publicKey,
		fetcher: vi.fn(async () => { throw Error("Provider egress forbidden in ingress test"); }),
	};
}
async function enrollmentFixture(config: ReturnType<typeof configuration>) {
	const value: Authorization = {
		contract_version: 1, purpose: "surface_enrollment", action: "authorize", operation_id: operation(),
		authorization_id: "private-widget-ticket",
		consent: { nonce: base64Url(new Uint8Array(32).fill(2).buffer), action_id: "widget-action",
			generation_id: "widget-generation", plan_digest: "a".repeat(64), expires_at_ms: expiry },
		enrollment: {
			contract_version: 1, purpose: "surface_push", action: "enrol", operation_id: operation(),
			delegation_id: "private-widget-delegation", expected_revision: 0, approval_reference: "fixture-consent",
			install_id: "widget-install", device_binding: "1".repeat(64), owner_binding: "2".repeat(64),
			grant_binding: "3".repeat(64), source_binding: "4".repeat(64), binding_id: "5".repeat(64), public_key: jwk,
			policy: { token_role: "widget", platform: "ios", apns_environment: "sandbox", activity_profile: null,
				external_content_allowed: false, original_grant_expires_at_ms: expiry,
				target: { app_bundle_id: "dev.synthetic.ios", extension_bundle_id: "dev.synthetic.ios.widget", widget_kind: "fixture" },
				max_operations: 4, max_events: 2, max_challenges: 1 },
		},
	};
	const authorize = createSurfaceEnrollment({ env: config.env, now: config.now });
	const response = await authorize(new Request("https://api.djconnect.dev" + prefix + "enrollment/operator/authorize", {
		method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + operator },
		body: JSON.stringify(value),
	}));
	expect(response.status).toBe(200);
	const { credential } = await response.json<{ credential: string }>();
	const payload: Redemption = { contract_version: 1, purpose: "surface_enrollment", action: "redeem",
		authorization_id: value.authorization_id, consent: value.consent, enrollment: value.enrollment };
	return { payload, credential: "Bearer " + credential };
}
async function statement(payload: Statement) {
	return { payload, signature: base64Url(await crypto.subtle.sign(signing, purposeKey.privateKey,
		signingBytes(prefix + "issuer/" + payload.action, payload))) };
}

it("carries the original app proofs through the real handlers with no Access headers", async () => {
	const config = configuration();
	let generation = config.credentialGeneration;
	let retireAfterReply = false;
	let retiredReplyStatus: number | undefined;
	const ingress = createPrivateWidgetIngress({ ...config, isCredentialCurrent: g => g === generation });
	const assertion = await jwt();
	const { payload, credential } = await enrollmentFixture(config);
	const create = composition.createSurfaceService;
	const forwarded: { path: string; headers: Record<string, string> }[] = [];
	const spy = vi.spyOn(composition, "createSurfaceService").mockImplementation(options => {
		const service = create(options);
		return { ...service, async handle(req) {
			forwarded.push({ path: new URL(req.url).pathname, headers: Object.fromEntries(req.headers) });
			const response = await service.handle(req);
			if (retireAfterReply) {
				retiredReplyStatus = response.status;
				generation++;
			}
			return response;
		} };
	});
	try {
		const signature = base64Url(await crypto.subtle.sign(signing, purposeKey.privateKey, redemptionBytes(payload)));
		const redeem = await ingress(request("enrollment/redeem", { payload, signature }, assertion, credential), context);
		expect(await redeem.json()).toMatchObject({ success: true, state: "enrolled" });
		const challengeInput: Statement = { contract_version: 1, purpose: "surface_push", action: "challenge",
			delegation_id: payload.enrollment.delegation_id, delegation_revision: 1, key_thumbprint: await thumbprint(jwk),
			operation_id: operation() };
		const challenge = await ingress(request("issuer/challenge", await statement(challengeInput), assertion), context);
		expect(challenge.status).toBe(200);
		const { challenge_id, nonce, scope_digest } = await challenge.json<{ challenge_id: string; nonce: string; scope_digest: string }>();
		const issue = await ingress(request("issuer/issue", await statement({
			...challengeInput, action: "issue", challenge_id, nonce, scope_digest,
		}), assertion), context);
		expect(issue.status).toBe(200);
		const relay = "Bearer " + (await issue.json<{ credential: string }>()).credential;
		const { policy, binding_id, device_binding, owner_binding } = payload.enrollment;
		const register = { contract_version: 1, registration_id: "widget-fixture", generation: "original", revision: 1,
			operation_id: operation(), binding_id, device_binding, owner_binding, expires_at_ms: expiry,
			token_role: "widget", platform: policy.platform, apns_environment: policy.apns_environment,
			target: { ...policy.target, instance_id: "widget-instance" }, apns_token: "01".repeat(32) };
		const response = await ingress(request("register", register, assertion, relay), context);
		expect(await response.json()).toMatchObject({ success: true, state: "registered" });
		expect(forwarded).toEqual([
			{ path: prefix + "enrollment/redeem", headers: { "content-type": "application/json", authorization: credential } },
			{ path: prefix + "issuer/challenge", headers: { "content-type": "application/json" } },
			{ path: prefix + "issuer/issue", headers: { "content-type": "application/json" } },
			{ path: prefix + "register", headers: { "content-type": "application/json", authorization: relay } },
		]);
		retireAfterReply = true;
		const { contract_version, registration_id, generation: targetGeneration, revision, operation_id } = register;
		const status = await ingress(request("status", {
			contract_version, registration_id, generation: targetGeneration, revision, operation_id,
			binding_id, device_binding, owner_binding,
		}, assertion, relay), context);
		expect(retiredReplyStatus).toBe(200);
		expect(status.status).toBe(503);
		expect(await status.json()).toMatchObject({ success: false, error: "surface_service_unavailable" });
		expect(config.fetcher).not.toHaveBeenCalled();
	} finally { spy.mockRestore(); }
});

it("rejects other Access identities and management paths before touching the handlers", async () => {
	const config = configuration();
	const resolve = vi.fn(config.resolveVerificationKey);
	const ingress = createPrivateWidgetIngress({ ...config, resolveVerificationKey: resolve });
	const good = await jwt();
	const validLookingBearer = "Bearer djcs_" + "A".repeat(43);
	for (const claims of [{ aud: ["other"] }, { common_name: "other.access" }, { exp: seconds }, { sub: "user" }]) {
		const response = await ingress(request("status", {}, await jwt(claims), validLookingBearer), context);
		expect(response.status).toBe(403);
	}
	for (const path of ["issuer/operator/enrol", "issuer/operator/withdraw", "enrollment/operator/authorize",
		"enrollment/operator/revoke", "status?target=other"]) {
		expect((await ingress(request(path, {}, good, "Bearer " + operator), context)).status).toBe(404);
	}
	expect(resolve).not.toHaveBeenCalled();
	const wrongProof = await ingress(request("status", {}, good, validLookingBearer), context);
	expect(wrongProof.status).toBe(401);
	expect(await wrongProof.json()).toMatchObject({ success: false, error: "surface_auth_required" });
});

it("rechecks the credential generation after key resolution", async () => {
	const config = configuration();
	let generation = 4;
	const old = createPrivateWidgetIngress({ ...config, isCredentialCurrent: g => g === generation,
		resolveVerificationKey: async () => { generation++; return accessKey.publicKey; } });
	const proof = "Bearer djcs_" + "A".repeat(43);
	expect((await old(request("status", {}, await jwt(), proof), context)).status).toBe(403);
});

it.each(["DB", "APNS_KEY_ID"] as const)("retires the ingress after in-place %s drift", async field => {
	const config = configuration();
	const ingress = createPrivateWidgetIngress(config);
	const assertion = await jwt();
	const proof = "Bearer djcs_" + "A".repeat(43);
	const status = () => ingress(request("status", {}, assertion, proof), context);
	expect((await status()).status).toBe(401);

	const { DB, APNS_KEY_ID } = config.env;
	if (field === "DB") {
		config.env.DB = { prepare: vi.fn(() => { throw Error("Replacement DB must not be used"); }) } as unknown as D1Database;
	} else {
		config.env.APNS_KEY_ID = "replacement-provider-key";
	}
	const compose = vi.spyOn(composition, "createSurfaceService");
	try {
		expect((await status()).status).toBe(403);
		config.env.DB = DB;
		config.env.APNS_KEY_ID = APNS_KEY_ID;
		expect((await status()).status).toBe(403);
		expect(compose).not.toHaveBeenCalled();
		expect(config.fetcher).not.toHaveBeenCalled();
	} finally { compose.mockRestore(); }
});
