import { createExecutionContext, env } from "cloudflare:test";
import { beforeAll, expect, it, vi } from "vitest";
import worker, { createWidgetHaDevWorker, WidgetEnrollmentOperator } from "../../src/surface-push/widget-ha-dev-worker";
import firstKeySchema from "./first-key.sql?raw";
import coreAuthoritySchema from "./core-authority.sql?raw";
import credentialSchema from "../../migrations/0002_install_tokens.sql?raw";
import bootstrapSchema from "../../migrations/0004_bootstrap_proofs.sql?raw";
import retirementVector from "../native-push-mvp/first-key-retirement-vector.json";
import currentnessVector from "../native-push-mvp/first-key-currentness-vector.json";
import { issueBootstrapProofHandler, issueInstallTokenHandler } from "../../src/handlers/install";
import type { AppEnv } from "../../src/types";
import { issueInstallToken } from "../../src/repositories/installTokens";
import { base64Encode, base64Url } from "../../src/crypto";
import { firstKeyAudience, firstKeyRegisterBytes, firstKeyStatusBytes, type FirstKeyChallenge, type FirstKeyStatusChallenge } from "../../src/native-push/first-key-wire";
import { createWidgetFirstKeyRetirementHandler, retireWidgetFirstKeyPair,
	type CoreCurrentnessAuthority, type WidgetFirstKeyPolicy } from "../../src/native-push/first-key-service";
import { createWidgetFirstKeyAppleVerifier } from "../../src/native-push/first-key-apple";
import { createWidgetInstallIssuer } from "../../src/native-push/widget-install-issuer";
import { createWidgetCoreHaDevWorker } from "../../src/native-push/widget-core-ha-dev-worker";
import { canonical } from "../../src/surface-push/wire";

const origin = "https://widget.fixture.invalid";
const operatorOrigin = "https://widget-enrollment.internal";
const prefix = "/v1/push/surface/";
const operatorSecret = "local-enrollment-fixture";
const local = env as unknown as { WIDGET_HA_DEV_DB: D1Database; WIDGET_PILOT_MODE: string };
const fixture = () => ({
	WIDGET_WORKER_VERSION: { id: crypto.randomUUID(), tag: "fixture", timestamp: "fixture" },
	WIDGET_PILOT_MODE: "transport-v1",
	WIDGET_PILOT_ORIGIN: origin,
	WIDGET_ACCESS_ISSUER: "https://widget-fixture.cloudflareaccess.com",
	WIDGET_ACCESS_AUDIENCE: "fixture-audience",
	WIDGET_ACCESS_CLIENT_ID: "fixture.access",
	WIDGET_ACCESS_GENERATION: "1",
	WIDGET_PILOT_EXPIRES_AT_MS: String(Date.now() + 30_000),
	WIDGET_HA_DEV_DB: local.WIDGET_HA_DEV_DB,
	WIDGET_TOKEN_ENCRYPTION_KEY: btoa("0123456789abcdef0123456789abcdef"),
	WIDGET_ENROLLMENT_OPERATOR_SECRET: operatorSecret,
});

function post(path: string, host = origin, bearer?: string) {
	const headers = new Headers({ "content-type": "application/json" });
	if (bearer) headers.set("authorization", "Bearer " + bearer);
	return new Request(host + prefix + path, { method: "POST", headers, body: "{}" });
}

it("binds only local WidgetKit D1 and closes by default", async () => {
	const config = fixture();
	expect(await config.WIDGET_HA_DEV_DB.prepare("SELECT 1 AS probe").first("probe")).toBe(1);
	expect(Object.keys(local).filter(key => !key.startsWith("__VITEST_POOL_WORKERS_")).sort()).toEqual(["WIDGET_HA_DEV_DB", "WIDGET_PILOT_MODE", "WIDGET_WORKER_VERSION"]);
	const ctx = createExecutionContext();
	expect((await worker.fetch(post("status"), local, ctx)).status).toBe(503);
	expect((await worker.fetch(post("status"), { ...config, WIDGET_PILOT_EXPIRES_AT_MS: "1" }, ctx)).status).toBe(503);
});

it("denies public management, missing machine admission and the APNs event route", async () => {
	const config = fixture();
	const ctx = createExecutionContext();
	expect((await worker.fetch(post("enrollment/operator/authorize", origin, operatorSecret), config, ctx)).status).toBe(404);
	expect((await worker.fetch(post("status"), config, ctx)).status).toBe(403);
	expect((await worker.fetch(post("event"), config, ctx)).status).toBe(404);
});

it("exposes only authorize and revoke through the named operator with existing proof", async () => {
	const ctx = createExecutionContext();
	const operator = new WidgetEnrollmentOperator(ctx, fixture());
	expect((await operator.fetch(post("enrollment/redeem", operatorOrigin, operatorSecret))).status).toBe(404);
	for (const action of ["authorize", "revoke"]) {
		const path = "enrollment/operator/" + action;
		expect((await operator.fetch(post(path, origin, operatorSecret))).status).toBe(404);
		expect((await operator.fetch(post(path, operatorOrigin))).status).toBe(401);
		expect((await operator.fetch(post(path, operatorOrigin, operatorSecret))).status).toBe(400);
	}
});

it.each(["public", "operator"] as const)("latches a shared D1 replacement detected by %s", async first => {
	const config = fixture();
	const ctx = createExecutionContext();
	const operator = new WidgetEnrollmentOperator(ctx, config);
	const publicStatus = () => worker.fetch(post("status"), config, ctx);
	const operationId = Date.now().toString(16).padStart(12, "0").replace(/^(.{8})(.{4})$/, "$1-$2") +
		"-7000-8000-000000000001";
	const operatorRequest = (bearer?: string) => operator.fetch(new Request(
		operatorOrigin + prefix + "enrollment/operator/revoke", {
			method: "POST",
			headers: { "content-type": "application/json", ...(bearer ? { authorization: "Bearer " + bearer } : {}) },
			body: JSON.stringify({ contract_version: 1, purpose: "surface_enrollment", action: "revoke",
				operation_id: operationId, authorization_id: "pilot-fixture" }),
		}));
	expect((await publicStatus()).status).toBe(403);
	expect((await operatorRequest()).status).toBe(401);
	const prepare = vi.fn(() => { throw new Error("Replacement D1 must not be accessed"); });
	config.WIDGET_HA_DEV_DB = { prepare } as unknown as D1Database;
	if (first === "public") expect((await publicStatus()).status).toBe(503);
	else expect((await operatorRequest(operatorSecret)).status).toBe(503);
	expect((await operatorRequest(operatorSecret)).status).toBe(503);
	expect((await publicStatus()).status).toBe(503);
	config.WIDGET_HA_DEV_DB = local.WIDGET_HA_DEV_DB;
	expect((await publicStatus()).status).toBe(503);
	expect((await operatorRequest(operatorSecret)).status).toBe(503);
	expect(prepare).not.toHaveBeenCalled();
	// A different env wrapper does not reset a retired version.
	expect((await worker.fetch(post("status"), { ...config }, ctx)).status).toBe(503);
	// A new immutable Worker version has its own captured composition.
	expect((await worker.fetch(post("status"), fixture(), ctx)).status).toBe(403);
});

const keyPrefix = "/v1/push/native/key/";
const es256 = { name: "ECDSA", hash: "SHA-256" };
const digest = async (value: BufferSource) => new Uint8Array(await crypto.subtle.digest("SHA-256", value));
const hex = (value: Uint8Array) => Array.from(value, byte => byte.toString(16).padStart(2, "0")).join("");

beforeAll(async () => {
	for (const statement of (credentialSchema + bootstrapSchema + firstKeySchema + coreAuthoritySchema).split(";").filter(part => part.trim())) {
		await local.WIDGET_HA_DEV_DB.prepare(statement).run();
	}
});

it("closes the dedicated Core Worker and binds signed Access, issuer, first key and retirement to one D1", async () => {
	const db = local.WIDGET_HA_DEV_DB;
	const signing = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
		publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" }, false, ["sign", "verify"]);
	const resolve = vi.fn(async () => signing.publicKey);
	const selected = createWidgetCoreHaDevWorker(() => resolve);
	const clientId = crypto.randomUUID();
	const scope = crypto.randomUUID();
	const install = { ha_install_id: crypto.randomUUID(), device_id: crypto.randomUUID(), client_type: "ios",
		integration: "djconnect_hacs", integration_version: "fixture" };
	const config = {
		WIDGET_CORE_MODE: "first-key-v1", WIDGET_CORE_ORIGIN: origin, WIDGET_CORE_ACCESS_ISSUER: "https://core-fixture.cloudflareaccess.com",
		WIDGET_CORE_ACCESS_AUDIENCE: "core-only", WIDGET_CORE_ACCESS_CLIENT_ID: clientId, WIDGET_CORE_POLICY_ID: "policy-fixture",
		WIDGET_CORE_EXPIRES_AT_MS: String(Date.now() + 120_000),
		WIDGET_CORE_APP_ID: "ABCDEFGHIJ.example.widget", WIDGET_CORE_APP_BUILD: "1", WIDGET_HA_DEV_DB: db,
	};
	const makeJwt = async (changes: Record<string, unknown> = {}) => {
		const encoded = (value: unknown) => base64Url(new TextEncoder().encode(JSON.stringify(value)).buffer as ArrayBuffer);
		const now = Math.floor(Date.now() / 1000);
		const data = encoded({ alg: "RS256", kid: "fixture-key" }) + "." + encoded({
			iss: config.WIDGET_CORE_ACCESS_ISSUER, aud: [config.WIDGET_CORE_ACCESS_AUDIENCE],
			common_name: clientId, type: "app", sub: "", iat: now, exp: now + 60, ...changes,
		});
		return data + "." + base64Url(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signing.privateKey,
			new TextEncoder().encode(data)));
	};
	const jwt = await makeJwt();
	const ctx = { access: {} } as ExecutionContext;
	const send = (path: string, body: unknown, options: { jwt?: string; bearer?: string; decision?: string;
		ctx?: ExecutionContext; config?: typeof config } = {}) => selected.fetch(new Request(origin + path, {
		method: "POST", headers: { "content-type": "application/json", "cf-access-jwt-assertion": options.jwt ?? jwt,
			...(options.bearer ? { authorization: "Bearer " + options.bearer } : {}),
			...(options.decision ? { "x-djc-first-key-currentness": options.decision } : {}) },
		body: canonical(body),
	}), options.config ?? config, options.ctx ?? ctx);
	const bootstrap = "/v1/install/bootstrap-proof";
	const exchange = "/v1/install/token";
	expect((await send(bootstrap, install, { config: { ...config, WIDGET_CORE_MODE: "closed" } })).status).toBe(503);
	expect((await send(bootstrap, install, { ctx: createExecutionContext() })).status).toBe(403);
	expect((await send(bootstrap, install, { jwt: await makeJwt({ aud: ["another-service"] }) })).status).toBe(403);
	expect((await send(bootstrap, install, { jwt: await makeJwt({ iat: Math.floor(Date.now() / 1000) - 31 }) })).status).toBe(403);
	expect(resolve).not.toHaveBeenCalled();
	const jwtParts = jwt.split(".");
	jwtParts[2] = (jwtParts[2][0] === "A" ? "B" : "A") + jwtParts[2].slice(1);
	expect((await send(bootstrap, install, { jwt: jwtParts.join(".") })).status).toBe(403);
	expect((await send(bootstrap, install)).status).toBe(403);
	await db.prepare("INSERT INTO widget_core_machines VALUES (?, ?, ?, ?, 1)").bind(clientId, scope, install.ha_install_id, install.device_id).run();
	expect((await send(bootstrap, { ...install, device_id: "foreign-device" })).status).toBe(403);
	expect((await send("/v1/push/surface/event", {})).status).toBe(404);
	const issued = await send(bootstrap, install);
	expect(issued.status).toBe(200);
	const { bootstrap_proof } = await issued.json<{ bootstrap_proof: string }>();
	const exchanged = await send(exchange, { ...install, bootstrap_proof });
	expect(exchanged.status).toBe(200);
	const { id, token } = await exchanged.json<{ id: string; token: string }>();
	const pair = {
		contract_version: 1, operation_id: crypto.randomUUID(), pairing_generation: crypto.randomUUID(),
		pair_binding: hex(await digest(new TextEncoder().encode(scope))), owner_binding: "b".repeat(64),
		device_binding: "c".repeat(64), core_key_thumbprint: "d".repeat(64),
	};
	const now = Date.now();
	const decision = canonical({
		...pair, api_audience: firstKeyAudience, action: "challenge", decision_id: crypto.randomUUID(),
		install_credential_id: id, request_sha256: hex(await digest(new TextEncoder().encode(canonical(pair)))),
		issued_at_ms: now, expires_at_ms: now + 10_000, operation_expires_at_ms: null,
	});
	const challenge = keyPrefix + "challenge";
	expect((await send(challenge, pair, { bearer: token, decision })).status).toBe(403);
	await db.prepare("INSERT INTO widget_core_pair_authority VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)")
		.bind(scope, id, pair.operation_id, pair.pairing_generation, pair.pair_binding, pair.owner_binding,
			pair.device_binding, pair.core_key_thumbprint, 1).run();
	const reserved = await send(challenge, pair, { bearer: token, decision });
	expect(reserved.status).toBe(200);
	expect((await reserved.json<FirstKeyChallenge>()).install_credential_id).toBe(id);
	const retirement = { ...pair, api_audience: firstKeyAudience, event_id: pair.operation_id,
		install_credential_id: id, request_expires_at_ms: 1 };
	const retire = keyPrefix + "retire";
	expect((await send(retire, { ...retirement, owner_binding: "e".repeat(64) })).status).toBe(403);
	expect((await send(retire, retirement, { bearer: token })).status).toBe(403);
	await db.prepare("UPDATE install_tokens SET disabled = 1 WHERE id = ?").bind(id).run();
	expect((await send(retire, retirement)).status).toBe(200);
	expect(await db.prepare("SELECT pair_binding FROM widget_first_key_retirements WHERE pair_binding = ?")
		.bind(pair.pair_binding).first("pair_binding")).toBe(pair.pair_binding);
	await db.prepare("UPDATE widget_core_machines SET enabled = 0 WHERE access_client_id = ?").bind(clientId).run();
	expect((await send(bootstrap, install)).status).toBe(403);
});

async function firstKeyFixture(verifier: WidgetFirstKeyPolicy["verifyApple"] = async () => true,
	issueCredential: (db: D1Database) => Promise<{ id: string; token: string }> =
		db => issueInstallToken(db, { ha_install_id: crypto.randomUUID() }),
	authorizeCore?: CoreCurrentnessAuthority) {
	const config = fixture();
	config.WIDGET_PILOT_EXPIRES_AT_MS = String(Date.now() + 300_000);
	const db = config.WIDGET_HA_DEV_DB;
	const credential = await issueCredential(db);
	const prepare = vi.fn((sql: string) => db.prepare(sql));
	config.WIDGET_HA_DEV_DB = { prepare } as unknown as D1Database;
	const signer = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
	const spki = await crypto.subtle.exportKey("spki", signer.publicKey);
	const original = {
		contract_version: 1 as const, operation_id: crypto.randomUUID(), pairing_generation: crypto.randomUUID(),
		pair_binding: hex(await digest(new TextEncoder().encode(crypto.randomUUID()))),
		owner_binding: "b".repeat(64), device_binding: "c".repeat(64), core_key_thumbprint: hex(await digest(spki)),
	};
	const sign = async (bytes: BufferSource) => base64Url(await crypto.subtle.sign(es256, signer.privateKey, bytes));
	let current = true;
	const verifyApple = vi.fn(verifier);
	const isPairCurrent = vi.fn<WidgetFirstKeyPolicy["isPairCurrent"]>(async (credentialId, received) =>
		current && credentialId === credential.id && received.pair_binding === original.pair_binding);
	const selected = createWidgetHaDevWorker({
		id: crypto.randomUUID(), expiresAt: Date.now() + 240_000, isCurrent: () => true,
		isPairCurrent,
		verifyApple,
	}, authorizeCore);
	const dispatchRaw = (path: string, body: string, bearer = credential.token, headers?: Record<string, string>) =>
		selected.fetch(new Request(origin + keyPrefix + path, {
		method: "POST", headers: { ...headers, "content-type": "application/json", authorization: "Bearer " + bearer },
		body,
	}), config, createExecutionContext());
	const dispatch = (path: string, body: unknown, bearer = credential.token) => dispatchRaw(path, JSON.stringify(body), bearer);
	async function registerInput(requestChallenge = () => dispatch("challenge", original)) {
		const response = await requestChallenge();
		expect(response.status).toBe(200);
		const challenge = await response.json<FirstKeyChallenge>();
		expect(challenge.install_credential_id).toBe(credential.id);
		const transcript = firstKeyRegisterBytes(challenge, original);
		return { challenge, transcript, input: { ...original, ...challenge, core_public_key_spki_b64: base64Encode(spki),
			core_signature_b64url: await sign(transcript),
			apple_proof: { kind: "attestation", key_id_b64: base64Encode(new Uint8Array(32)), proof_b64: "AA==" } } };
	}
	return { db, credential, original, sign, dispatch, dispatchRaw, registerInput, prepare, verifyApple, isPairCurrent,
		retirePair() { current = false; } };
}

it("accepts a credential issued by the existing install handlers on the isolated D1 without exposing an issuer route", async () => {
	const payload = { ha_install_id: crypto.randomUUID(), device_id: crypto.randomUUID(), client_type: "ios" };
	const request = (path: string, body: unknown, bearer?: string) => new Request(origin + path, {
		method: "POST",
		headers: { "content-type": "application/json", ...(bearer ? { authorization: "Bearer " + bearer } : {}) },
		body: JSON.stringify(body),
	});
	const f = await firstKeyFixture(undefined, async db => {
		const issuerEnv = { DB: db, DJCONNECT_RELAY_SECRET: operatorSecret } as AppEnv;
		const bootstrap = await issueBootstrapProofHandler(request("/v1/install/bootstrap-proof", payload, operatorSecret), issuerEnv);
		expect(bootstrap.status).toBe(200);
		const { bootstrap_proof } = await bootstrap.json<{ bootstrap_proof: string }>();
		const installRequest = () => request("/v1/install/token", { ...payload, bootstrap_proof });
		const token = await issueInstallTokenHandler(installRequest(), issuerEnv);
		expect(token.status).toBe(200);
		await expect(issueInstallTokenHandler(installRequest(), issuerEnv)).rejects.toMatchObject({ status: 409 });
		return token.json<{ id: string; token: string }>();
	});
	const { challenge } = await f.registerInput();
	expect(challenge.install_credential_id).toBe(f.credential.id);
	const config = fixture();
	for (const path of ["/v1/install/bootstrap-proof", "/v1/pairing/bootstrap-proof", "/v1/install/token"]) {
		expect((await worker.fetch(request(path, payload, operatorSecret), config, createExecutionContext())).status).toBe(404);
	}
});

it("issues and exchanges a private bootstrap proof only under the original machine mapping", async () => {
	const payload = { ha_install_id: crypto.randomUUID(), device_id: crypto.randomUUID(), client_type: "ios",
		integration: "djconnect_hacs", integration_version: "fixture" };
	const request = (path: string, body: unknown, scope?: string) => new Request(origin + path, {
		method: "POST", headers: { "content-type": "application/json", ...(scope ? { "x-fixture-machine": scope } : {}) },
		body: canonical(body),
	});
	const f = await firstKeyFixture(undefined, async db => {
		const issuer = createWidgetInstallIssuer(db, origin, async (request, coordinates) => {
			const scopeId = request.headers.get("x-fixture-machine");
			return scopeId && canonical(coordinates) === canonical(payload) ? { scopeId, isCurrent: () => true } : null;
		});
		const bootstrap = "/v1/install/bootstrap-proof";
		const exchange = "/v1/install/token";
		expect((await issuer(request(bootstrap, payload))).status).toBe(403);
		expect((await issuer(request(bootstrap, { ...payload, device_id: "other" }, "first"))).status).toBe(403);
		const issued = await issuer(request(bootstrap, payload, "first"));
		expect(issued.status).toBe(200);
		const { bootstrap_proof, expires_at } = await issued.json<{ bootstrap_proof: string; expires_at: string }>();
		expect(Date.parse(expires_at) - Date.now()).toBeLessThanOrEqual(60_000);
		const body = { ...payload, bootstrap_proof };
		expect((await issuer(request(exchange, body, "changed-generation"))).status).toBe(403);
		const attempts = await Promise.all([issuer(request(exchange, body, "first")), issuer(request(exchange, body, "first"))]);
		expect(attempts.map(response => response.status).sort()).toEqual([200, 409]);
		return attempts.find(response => response.ok)!.json<{ id: string; token: string }>();
	});
	expect((await f.registerInput()).challenge.install_credential_id).toBe(f.credential.id);
});

it.each(["challenge", "register", "status/challenge", "status"])("leaves first-key %s closed without a selected verifier", async path => {
	const config = fixture();
	const request = new Request(origin + keyPrefix + path, { method: "POST", body: "unread" });
	const response = await worker.fetch(request, config, createExecutionContext());
	expect(response.status).toBe(503);
	expect(await response.json()).toEqual({ error: "widget_first_key_unavailable" });
	expect(request.bodyUsed).toBe(false);
});

it("commits one registration and consumes each status nonce once through the actual Worker and D1", async () => {
	const f = await firstKeyFixture();
	const { challenge, transcript, input } = await f.registerInput();
	expect(await (await f.dispatch("challenge", f.original)).json()).toEqual(challenge);
	expect((await f.dispatch("register", { ...input, owner_binding: "d".repeat(64) })).status).toBe(409);
	expect(f.verifyApple).not.toHaveBeenCalled();
	const responses = await Promise.all([f.dispatch("register", input), f.dispatch("register", input)]);
	expect(responses.map(response => response.status).sort()).toEqual([200, 409]);
	const receipt = await responses.find(response => response.ok)!.json<Record<string, unknown>>();
	expect(Object.keys(receipt).sort()).toEqual([
		"api_installation_id", "contract_version", "core_key_thumbprint", "expires_at_ms", "install_credential_id",
		"key_revision", "operation_id", "pairing_generation", "registry_generation", "state", "transcript_sha256",
	]);
	expect(receipt.transcript_sha256).toBe(hex(await digest(transcript)));
	expect(f.verifyApple.mock.calls[0].slice(0, 4)).toEqual([
		new Uint8Array([0]), input.apple_proof.key_id_b64, transcript, challenge.expires_at_ms,
	]);
	const lookup = {
		contract_version: 1, operation_id: receipt.operation_id,
		api_installation_id: receipt.api_installation_id, transcript_sha256: receipt.transcript_sha256,
	};
	const status = await (await f.dispatch("status/challenge", lookup)).json<FirstKeyStatusChallenge>();
	expect(status.status_nonce_expires_at_ms).toBeLessThanOrEqual(challenge.expires_at_ms);
	expect(await (await f.dispatch("status/challenge", lookup)).json()).toEqual(status);
	const statusInput = { ...status, core_signature_b64url: await f.sign(firstKeyStatusBytes(status)) };
	const reads = await Promise.all([f.dispatch("status", statusInput), f.dispatch("status", statusInput)]);
	expect(reads.map(response => response.status).sort()).toEqual([200, 409]);
	expect(await reads.find(response => response.ok)!.json()).toEqual(receipt);
	const next = await (await f.dispatch("status/challenge", lookup)).json<FirstKeyStatusChallenge>();
	expect(next.status_nonce_id).not.toBe(status.status_nonce_id);
	expect((await f.dispatch("status", statusInput)).status).toBe(409);
	f.retirePair();
	expect((await f.dispatch("status", { ...next, core_signature_b64url: await f.sign(firstKeyStatusBytes(next)) })).status).toBe(403);
});

it("refuses an assertion before any D1 access or Apple verification and leaves the challenge usable", async () => {
	const f = await firstKeyFixture();
	const { input } = await f.registerInput();
	f.prepare.mockClear();
	const response = await f.dispatch("register", { ...input, apple_proof: { ...input.apple_proof, kind: "assertion" } });
	expect(response.status).toBe(403);
	expect(await response.json()).toEqual({ error: "widget_first_key_proof_rejected" });
	expect(f.prepare).not.toHaveBeenCalled();
	expect(f.verifyApple).not.toHaveBeenCalled();
	expect((await f.dispatch("register", input)).status).toBe(200);
});

it("allows the full Apple proof within the register envelope and enforces the route byte limits", async () => {
	const f = await firstKeyFixture();
	const challengeBody = JSON.stringify(f.original);
	expect((await f.dispatchRaw("challenge", challengeBody.padEnd(16_384))).status).toBe(200);
	for (const route of ["challenge", "status/challenge", "status"]) {
		const response = await f.dispatchRaw(route, challengeBody.padEnd(16_385));
		expect(response.status).toBe(413);
		expect(await response.json()).toEqual({ error: "payload_too_large" });
	}

	const { input } = await f.registerInput();
	const withProof = (size: number) => JSON.stringify({
		...input, apple_proof: { ...input.apple_proof, proof_b64: base64Encode(new Uint8Array(size)) },
	});
	expect((await f.dispatchRaw("register", withProof(16_385))).status).toBe(400);
	const body = withProof(16_384);
	expect(body.length).toBeGreaterThan(16_384);
	const response = await f.dispatchRaw("register", body.padEnd(32_769));
	expect(response.status).toBe(413);
	expect(await response.json()).toEqual({ error: "payload_too_large" });
	expect(f.verifyApple).not.toHaveBeenCalled();
	expect((await f.dispatchRaw("register", body.padEnd(32_768))).status).toBe(200);
	expect(f.verifyApple).toHaveBeenCalledOnce();
});

it("refuses a rejected Apple proof and rechecks the exact D1 credential after successful verification", async () => {
	const f = await firstKeyFixture();
	const { input } = await f.registerInput();
	f.verifyApple.mockResolvedValueOnce(false);
	expect((await f.dispatch("register", input)).status).toBe(403);
	f.verifyApple.mockImplementationOnce(async () => {
		await f.db.prepare("UPDATE install_tokens SET disabled = 1 WHERE id = ?").bind(f.credential.id).run();
		return true;
	});
	expect((await f.dispatch("register", input)).status).toBe(409);
	expect(await f.db.prepare("SELECT receipt FROM widget_first_key WHERE credential_id = ?")
		.bind(f.credential.id).first("receipt")).toBeNull();
});

it("uses the real Apple verifier and rejects invalid attestation before any Apple network lookup", async () => {
	const f = await firstKeyFixture(createWidgetFirstKeyAppleVerifier({
		profile: "host_wake_apple_properties_attestation_v2",
		app_identifier: "ABCDEFGHIJ.example.fixture.host",
		app_attest_environment: "development",
		bundle_version: "1.0",
		launch_validation_category_b64: "AwAAAA==",
	}));
	const { input } = await f.registerInput();
	const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("Unexpected network access"));
	try {
		const response = await f.dispatch("register", input);
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "widget_first_key_proof_rejected" });
		expect(f.verifyApple).toHaveBeenCalledOnce();
		expect(fetchSpy).not.toHaveBeenCalled();
		expect(await f.db.prepare("SELECT receipt FROM widget_first_key WHERE credential_id = ?")
			.bind(f.credential.id).first("receipt")).toBeNull();
	} finally {
		fetchSpy.mockRestore();
	}
});

it("fences a retired pairing before reservation and at the registration write even when the Core check allows it", async () => {
	const f = await firstKeyFixture();
	const { input } = await f.registerInput();
	f.verifyApple.mockImplementationOnce(async () => {
		await retireWidgetFirstKeyPair(f.db, f.original.pair_binding);
		return true;
	});
	expect((await f.dispatch("register", input)).status).toBe(409);
	expect(await f.db.prepare("SELECT receipt FROM widget_first_key WHERE credential_id = ?")
		.bind(f.credential.id).first("receipt")).toBeNull();
	const newOperation = { ...f.original, operation_id: crypto.randomUUID() };
	expect((await f.dispatch("challenge", newOperation)).status).toBe(409);
	expect(await f.db.prepare("SELECT operation_id FROM widget_first_key WHERE operation_id = ?")
		.bind(newOperation.operation_id).first()).toBeNull();
	await retireWidgetFirstKeyPair(f.db, f.original.pair_binding);
	expect(await f.db.prepare("SELECT COUNT(*) AS count FROM widget_first_key_retirements WHERE pair_binding = ?")
		.bind(f.original.pair_binding).first("count")).toBe(1);
	const independent = await firstKeyFixture();
	expect((await independent.dispatch("challenge", independent.original)).status).toBe(200);
});

it("blocks the original receipt and its already issued status nonce after durable retirement", async () => {
	const f = await firstKeyFixture();
	const { input } = await f.registerInput();
	const receipt = await (await f.dispatch("register", input)).json<Record<string, unknown>>();
	const lookup = {
		contract_version: 1, operation_id: receipt.operation_id,
		api_installation_id: receipt.api_installation_id, transcript_sha256: receipt.transcript_sha256,
	};
	const status = await (await f.dispatch("status/challenge", lookup)).json<FirstKeyStatusChallenge>();
	const signed = { ...status, core_signature_b64url: await f.sign(firstKeyStatusBytes(status)) };
	f.isPairCurrent.mockImplementationOnce(async () => {
		await retireWidgetFirstKeyPair(f.db, f.original.pair_binding);
		return true;
	});
	expect((await f.dispatch("status", signed)).status).toBe(409);
	expect((await f.dispatch("status/challenge", lookup)).status).toBe(409);
	expect(await f.db.prepare("SELECT receipt FROM widget_first_key WHERE credential_id = ?")
		.bind(f.credential.id).first("receipt")).toBeTypeOf("string");
});

it("authenticates a canonical retirement and acknowledges the exact event after writing D1", async () => {
	const f = await firstKeyFixture();
	const event = {
		...f.original, api_audience: firstKeyAudience, event_id: f.original.operation_id,
		install_credential_id: f.credential.id, request_expires_at_ms: 1,
	};
	const body = canonical(event);
	const request = (raw = body) => new Request(origin + keyPrefix + "retire", {
		method: "POST", headers: { "content-type": "application/json" }, body: raw,
	});
	let admitted = false;
	const authorize = vi.fn(async (_request: Request, received: unknown) => admitted && canonical(received) === body);
	const retire = createWidgetFirstKeyRetirementHandler(f.db, origin, authorize);

	expect((await worker.fetch(request(), fixture(), createExecutionContext())).status).toBe(404);
	expect((await retire(request(body + "\n"))).status).toBe(400);
	expect(authorize).not.toHaveBeenCalled();
	expect((await retire(request())).status).toBe(403);
	admitted = true;
	expect((await retire(request(canonical({ ...event, owner_binding: "d".repeat(64) })))).status).toBe(403);
	expect(await f.db.prepare("SELECT pair_binding FROM widget_first_key_retirements WHERE pair_binding = ?")
		.bind(event.pair_binding).first()).toBeNull();

	// No reservation or active bearer is required once trusted authority resolves the historical tuple.
	await f.db.prepare("UPDATE install_tokens SET disabled = 1 WHERE id = ?").bind(f.credential.id).run();
	const expected = canonical({
		contract_version: 1, api_audience: firstKeyAudience, event_id: event.event_id,
		pair_binding: event.pair_binding, event_sha256: hex(await digest(new TextEncoder().encode(body))), state: "retired",
	});
	for (const response of await Promise.all([retire(request()), retire(request())])) {
		expect(response.status).toBe(200);
		expect(await response.text()).toBe(expected);
	}
	expect(await f.db.prepare("SELECT COUNT(*) AS count FROM widget_first_key_retirements WHERE pair_binding = ?")
		.bind(event.pair_binding).first("count")).toBe(1);
});

it("returns the exact acknowledgement encoded by Core for retire v1", async () => {
	const db = local.WIDGET_HA_DEV_DB;
	const retire = createWidgetFirstKeyRetirementHandler(db, origin, async (_request, event) =>
		canonical(event) === retirementVector.request);
	const response = await retire(new Request(origin + retirementVector.path, {
		method: "POST", headers: { "content-type": "application/json" }, body: retirementVector.request,
	}));
	expect(response.status).toBe(200);
	expect(await response.text()).toBe(retirementVector.ack);
});

it("requires independent currentness bound to each exact request and consumes each decision once", async () => {
	const f = await firstKeyFixture(undefined, undefined, async request =>
		request.headers.get("x-fixture-core-identity") === "admitted");
	const encodeDecision = async (action: string, body: unknown, originalDeadline: number | null,
		changes: Record<string, unknown> = {}) => {
		const now = Date.now();
		return canonical({
			...f.original, api_audience: firstKeyAudience, action, decision_id: crypto.randomUUID(),
			install_credential_id: f.credential.id, issued_at_ms: now,
			expires_at_ms: Math.min(now + 10_000, originalDeadline ?? Infinity),
			operation_expires_at_ms: originalDeadline,
			request_sha256: hex(await digest(new TextEncoder().encode(canonical(body)))), ...changes,
		});
	};
	const send = async (action: string, body: unknown, decision: string, admitted = true) =>
		f.dispatchRaw(action, canonical(body), f.credential.token, {
			"x-djc-first-key-currentness": decision,
			"x-fixture-core-identity": admitted ? "admitted" : "untrusted",
		});

	const decision = await encodeDecision("challenge", f.original, null);
	expect((await send("challenge", f.original, decision, false)).status).toBe(403);
	const expiredAt = Date.now() - 1;
	expect((await send("challenge", f.original, await encodeDecision("challenge", f.original, null,
		{ issued_at_ms: expiredAt - 1000, expires_at_ms: expiredAt }))).status).toBe(403);
	expect((await send("challenge", f.original, await encodeDecision("challenge", f.original, null,
		{ owner_binding: "d".repeat(64) }))).status).toBe(403);
	const { input, challenge } = await f.registerInput(async () => {
		const attempts = await Promise.all([send("challenge", f.original, decision), send("challenge", f.original, decision)]);
		expect(attempts.map(response => response.status).sort()).toEqual([200, 409]);
		return attempts.find(response => response.ok)!;
	});
	expect((await send("challenge", f.original, decision)).status).toBe(409);
	const freshRetry = await send("challenge", f.original, await encodeDecision("challenge", f.original, null));
	expect(await freshRetry.json()).toEqual(challenge);
	expect((await send("register", input, await encodeDecision("status", input, challenge.expires_at_ms))).status).toBe(403);
	expect(f.verifyApple).not.toHaveBeenCalled();
	const expiringDecision = await encodeDecision("register", input, challenge.expires_at_ms);
	const clock = vi.spyOn(Date, "now");
	try {
		f.verifyApple.mockImplementationOnce(async () => {
			clock.mockReturnValue(JSON.parse(expiringDecision).expires_at_ms);
			return true;
		});
		expect((await send("register", input, expiringDecision)).status).toBe(403);
	} finally {
		clock.mockRestore();
	}
	expect(await f.db.prepare("SELECT receipt FROM widget_first_key WHERE credential_id = ?")
		.bind(f.credential.id).first("receipt")).toBeNull();
	const accepted = await send("register", input, await encodeDecision("register", input, challenge.expires_at_ms));
	expect(accepted.status).toBe(200);
	const receipt = await accepted.json<Record<string, unknown>>();
	const lookup = {
		contract_version: 1, operation_id: receipt.operation_id,
		api_installation_id: receipt.api_installation_id, transcript_sha256: receipt.transcript_sha256,
	};
	const nonceDecision = await encodeDecision("status/challenge", lookup, challenge.expires_at_ms);
	const status = await (await send("status/challenge", lookup, nonceDecision)).json<FirstKeyStatusChallenge>();
	const statusRequest = { ...status, core_signature_b64url: await f.sign(firstKeyStatusBytes(status)) };
	const statusDecision = await encodeDecision("status", statusRequest, challenge.expires_at_ms, {
		expires_at_ms: Math.min(Date.now() + 9_000, status.status_nonce_expires_at_ms),
	});
	const substituted = { ...statusRequest, status_nonce: "A".repeat(43) };
	expect((await send("status", substituted, statusDecision)).status).toBe(403);
	expect(await (await send("status", statusRequest, statusDecision)).json()).toEqual(receipt);
	expect((await send("status/challenge", lookup, nonceDecision)).status).toBe(409);
	expect((await send("status", statusRequest, statusDecision)).status).toBe(409);
	await retireWidgetFirstKeyPair(f.db, f.original.pair_binding);
	expect((await send("status/challenge", lookup, await encodeDecision("status/challenge", lookup, challenge.expires_at_ms))).status).toBe(409);
});

it("matches the portable currentness header and canonical status request vector", async () => {
	const request = JSON.parse(currentnessVector.request);
	const decision = JSON.parse(currentnessVector.header);
	expect(canonical(request)).toBe(currentnessVector.request);
	expect(canonical(decision)).toBe(currentnessVector.header);
	expect(decision.request_sha256).toBe(hex(await digest(new TextEncoder().encode(currentnessVector.request))));
	expect(decision.expires_at_ms).toBe(request.status_nonce_expires_at_ms);
});

it("cannot renew an expired registration challenge or commit at its original deadline", async () => {
	const f = await firstKeyFixture();
	const { challenge, input } = await f.registerInput();
	const clock = vi.spyOn(Date, "now").mockReturnValue(challenge.expires_at_ms);
	try {
		expect((await f.dispatch("challenge", f.original)).status).toBe(409);
		expect((await f.dispatch("register", input)).status).toBe(409);
		expect(f.verifyApple).not.toHaveBeenCalled();
	} finally {
		clock.mockRestore();
	}
});
