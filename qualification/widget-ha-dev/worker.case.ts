import { createExecutionContext, env } from "cloudflare:test";
import { beforeAll, expect, it, vi } from "vitest";
import worker, { createWidgetHaDevWorker, WidgetEnrollmentOperator } from "../../src/surface-push/widget-ha-dev-worker";
import firstKeySchema from "./first-key.sql?raw";
import credentialSchema from "../../migrations/0002_install_tokens.sql?raw";
import { issueInstallToken } from "../../src/repositories/installTokens";
import { base64Encode, base64Url } from "../../src/crypto";
import { firstKeyRegisterBytes, firstKeyStatusBytes, type FirstKeyChallenge, type FirstKeyStatusChallenge } from "../../src/native-push/first-key-wire";

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
	for (const statement of (credentialSchema + firstKeySchema).split(";").filter(part => part.trim())) {
		await local.WIDGET_HA_DEV_DB.prepare(statement).run();
	}
});

async function firstKeyFixture() {
	const config = fixture();
	config.WIDGET_PILOT_EXPIRES_AT_MS = String(Date.now() + 300_000);
	const db = config.WIDGET_HA_DEV_DB;
	const credential = await issueInstallToken(db, { ha_install_id: crypto.randomUUID() });
	const signer = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
	const spki = await crypto.subtle.exportKey("spki", signer.publicKey);
	const original = {
		contract_version: 1 as const, operation_id: crypto.randomUUID(), pairing_generation: crypto.randomUUID(),
		pair_binding: hex(await digest(new TextEncoder().encode(crypto.randomUUID()))),
		owner_binding: "b".repeat(64), device_binding: "c".repeat(64), core_key_thumbprint: hex(await digest(spki)),
	};
	const sign = async (bytes: BufferSource) => base64Url(await crypto.subtle.sign(es256, signer.privateKey, bytes));
	let current = true;
	const verifyApple = vi.fn(async (_proof: unknown, _hash: Uint8Array) => true);
	const selected = createWidgetHaDevWorker({
		id: crypto.randomUUID(), expiresAt: Date.now() + 240_000, isCurrent: () => true,
		isPairCurrent: async (credentialId, received) => current && credentialId === credential.id && received.pair_binding === original.pair_binding,
		verifyApple,
	});
	const dispatch = (path: string, body: unknown, bearer = credential.token) => selected.fetch(new Request(origin + keyPrefix + path, {
		method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + bearer },
		body: JSON.stringify(body),
	}), config, createExecutionContext());
	async function registerInput() {
		const response = await dispatch("challenge", original);
		expect(response.status).toBe(200);
		const challenge = await response.json<FirstKeyChallenge>();
		expect(challenge.install_credential_id).toBe(credential.id);
		const transcript = firstKeyRegisterBytes(challenge, original);
		return { challenge, transcript, input: { ...original, ...challenge, core_public_key_spki_b64: base64Encode(spki),
			core_signature_b64url: await sign(transcript),
			apple_proof: { kind: "attestation", key_id_b64: base64Encode(new Uint8Array(32)), proof_b64: "AA==" } } };
	}
	return { db, credential, original, sign, dispatch, registerInput, verifyApple, retirePair() { current = false; } };
}

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
	expect(f.verifyApple.mock.calls[0][1]).toEqual(await digest(transcript));
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
