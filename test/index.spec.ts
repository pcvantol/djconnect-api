import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index";
import { apnsEndpoint, buildApnsPayload } from "../src/apns";

const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
const EXAMPLE_RELAY_SECRET = "example-relay-secret";
const EXAMPLE_APNS_TOKEN_ENCRYPTION_KEY = btoa("0123456789abcdef0123456789abcdef");
const AUTH = `Bearer ${EXAMPLE_RELAY_SECRET}`;

const testEnv = {
	...env,
	APNS_TEAM_ID: "ZEML4LPXH4",
	APNS_KEY_ID: "929NDF6UYK",
	APNS_PRIVATE_KEY: "",
	APNS_TOPIC_IOS: "dev.djconnect.ios",
	APNS_TOPIC_MACOS: "dev.djconnect.mac",
	APNS_TOPIC_WATCHOS: "dev.djconnect.watch",
	APNS_ENVIRONMENT: "sandbox",
	APNS_TOKEN_ENCRYPTION_KEY: EXAMPLE_APNS_TOKEN_ENCRYPTION_KEY,
	DJCONNECT_RELAY_SECRET: EXAMPLE_RELAY_SECRET,
};

describe("DJConnect API worker", () => {
	beforeAll(async () => {
		for (const statement of TEST_SCHEMA.split(";").map((part) => part.trim()).filter(Boolean)) {
			await env.DB.prepare(statement).run();
		}
	});

	beforeEach(async () => {
		testEnv.APNS_PRIVATE_KEY = await makePrivateKeyPem();
		await env.DB.exec("DELETE FROM relay_events");
		await env.DB.exec("DELETE FROM registrations");
		await env.DB.exec("DELETE FROM install_tokens");
		vi.restoreAllMocks();
	});

	it("requires auth for register and event calls", async () => {
		const register = await dispatch("/v1/push/register", {});
		expect(register.status).toBe(401);

		const event = await dispatch("/v1/push/event", {});
		expect(event.status).toBe(401);
	});

	it("issues per-install tokens with bootstrap auth", async () => {
		const response = await dispatch("/v1/install/token", {
			ha_install_id: "example-ha-install",
			ha_user_hash: "example-user-hash",
			label: "example-ha",
		}, AUTH);

		expect(response.status).toBe(200);
		const body = await response.json() as { ok: boolean; token: string; token_hash: string };
		expect(body.ok).toBe(true);
		expect(body.token).toMatch(/^djci_/);
		expect(body.token_hash).toHaveLength(64);

		const row = await env.DB.prepare("SELECT token_hash, disabled FROM install_tokens WHERE ha_install_id = ?").bind("example-ha-install").first<{ token_hash: string; disabled: number }>();
		expect(row).toEqual({ token_hash: body.token_hash, disabled: 0 });
		expect(row?.token_hash).not.toBe(body.token);
	});

	it("does not allow the bootstrap secret for push calls", async () => {
		const response = await dispatch("/v1/push/register", registerPayload(), AUTH);
		expect(response.status).toBe(401);
	});

	it("rejects install tokens for a different HA install", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		const response = await dispatch("/v1/push/register", {
			...registerPayload(),
			ha_install_id: "other-ha-install",
		}, installAuth);

		expect(response.status).toBe(403);
	});

	it("rotates per-install tokens and disables the previous token", async () => {
		const oldAuth = await issueInstallAuth("example-ha-install");
		const rotate = await dispatch("/v1/install/rotate", {
			ha_install_id: "example-ha-install",
		}, oldAuth);
		expect(rotate.status).toBe(200);
		const body = await rotate.json() as { token: string };
		const newAuth = `Bearer ${body.token}`;

		const oldRegister = await dispatch("/v1/push/register", registerPayload(), oldAuth);
		expect(oldRegister.status).toBe(401);

		const newRegister = await dispatch("/v1/push/register", registerPayload(), newAuth);
		expect(newRegister.status).toBe(200);
	});

	it("builds an APNs payload without prompts, responses, or secrets", () => {
		const payload = buildApnsPayload({
			event_type: "ask_dj_response",
			history_revision: "42",
			client_message_id: "msg-1",
			open_target: "history",
		});
		const serialized = JSON.stringify(payload);
		expect(serialized).toContain("Ask DJ heeft geantwoord.");
		expect(serialized).not.toMatch(/prompt|response_text|assistant|spotify|token|secret|history_memory/i);
	});

	it("registers and unregisters a device in D1", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		const register = await dispatch("/v1/push/register", registerPayload(), installAuth);
		expect(register.status).toBe(200);
		const body = await register.json() as { ok: boolean; apns_token_hash: string };
		expect(body.ok).toBe(true);
		expect(body.apns_token_hash).toHaveLength(64);

		const row = await env.DB.prepare(`
			SELECT apns_token, apns_token_ciphertext, apns_token_nonce, apns_token_key_version, disabled, invalid
			FROM registrations
			WHERE device_id = ?
		`).bind("example-device").first<{
			apns_token: string | null;
			apns_token_ciphertext: string | null;
			apns_token_nonce: string | null;
			apns_token_key_version: string | null;
			disabled: number;
			invalid: number;
		}>();
		expect(row?.disabled).toBe(0);
		expect(row?.invalid).toBe(0);
		expect(row?.apns_token).toBeNull();
		expect(row?.apns_token_ciphertext).toEqual(expect.any(String));
		expect(row?.apns_token_ciphertext).not.toContain("example-apns-token");
		expect(row?.apns_token_nonce).toEqual(expect.any(String));
		expect(row?.apns_token_key_version).toEqual(expect.any(String));

		const unregister = await dispatch("/v1/push/unregister", {
			ha_install_id: "example-ha-install",
			device_id: "example-device",
		}, installAuth);
		expect(unregister.status).toBe(200);

		const updated = await env.DB.prepare("SELECT disabled FROM registrations WHERE device_id = ?").bind("example-device").first<{ disabled: number }>();
		expect(updated?.disabled).toBe(1);
	});

	it("disables a registration when APNs reports an invalid token", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		await dispatch("/v1/push/register", registerPayload(), installAuth);
		const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response(JSON.stringify({ reason: "BadDeviceToken" }), { status: 400 }),
		);

		const event = await dispatch("/v1/push/event", {
			ha_install_id: "example-ha-install",
			event_type: "ask_dj_response",
			history_revision: 7,
		}, installAuth);
		expect(event.status).toBe(200);
		expect(fetchMock).toHaveBeenCalledOnce();
		expect(fetchMock.mock.calls[0]?.[0]).toBe("https://api.sandbox.push.apple.com/3/device/example-apns-token");

		const row = await env.DB.prepare("SELECT disabled, invalid, last_error_code FROM registrations WHERE device_id = ?").bind("example-device").first<{ disabled: number; invalid: number; last_error_code: string }>();
		expect(row).toEqual({ disabled: 1, invalid: 1, last_error_code: "BadDeviceToken" });
	});

	it("selects sandbox and production APNs endpoints", () => {
		expect(apnsEndpoint("sandbox", "abc")).toBe("https://api.sandbox.push.apple.com/3/device/abc");
		expect(apnsEndpoint("production", "abc")).toBe("https://api.push.apple.com/3/device/abc");
	});
});

async function dispatch(path: string, body: unknown, authorization?: string): Promise<Response> {
	const request = new IncomingRequest(`https://api.djconnect.dev${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			...(authorization ? { authorization } : {}),
		},
		body: JSON.stringify(body),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, testEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function issueInstallAuth(haInstallId: string): Promise<string> {
	const response = await dispatch("/v1/install/token", { ha_install_id: haInstallId }, AUTH);
	expect(response.status).toBe(200);
	const body = await response.json() as { token: string };
	return `Bearer ${body.token}`;
}

function registerPayload() {
	return {
		ha_install_id: "example-ha-install",
		ha_user_hash: "example-user-hash",
		device_id: "example-device",
		client_type: "ios",
		apns_token: "example-apns-token",
		apns_environment: "sandbox",
		app_bundle_id: "dev.djconnect.ios",
		app_version: "1.0.0",
		locale: "nl-NL",
		categories: ["ask_dj"],
	};
}

async function makePrivateKeyPem(): Promise<string> {
	const keyPair = await crypto.subtle.generateKey(
		{ name: "ECDSA", namedCurve: "P-256" },
		true,
		["sign", "verify"],
	);
	const pkcs8 = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
	const base64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)));
	const begin = "-----BEGIN" + " PRIVATE KEY-----";
	const end = "-----END" + " PRIVATE KEY-----";
	return `${begin}\n${base64.match(/.{1,64}/g)?.join("\n")}\n${end}`;
}

const TEST_SCHEMA = `
CREATE TABLE IF NOT EXISTS registrations (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	ha_user_hash TEXT,
	device_id TEXT NOT NULL,
	client_type TEXT NOT NULL CHECK (client_type IN ('ios', 'macos', 'watchos')),
	apns_token_hash TEXT NOT NULL,
	apns_token TEXT,
	apns_token_ciphertext TEXT,
	apns_token_nonce TEXT,
	apns_token_key_version TEXT,
	apns_environment TEXT NOT NULL CHECK (apns_environment IN ('sandbox', 'production')),
	topic TEXT NOT NULL,
	app_bundle_id TEXT,
	app_version TEXT,
	locale TEXT,
	categories_json TEXT NOT NULL DEFAULT '[]',
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	invalid INTEGER NOT NULL DEFAULT 0 CHECK (invalid IN (0, 1)),
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now')),
	last_success_at TEXT,
	last_error_code TEXT,
	UNIQUE (ha_install_id, device_id, client_type, apns_token_hash)
);

CREATE TABLE IF NOT EXISTS install_tokens (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	ha_user_hash TEXT,
	token_hash TEXT NOT NULL UNIQUE,
	token_prefix TEXT NOT NULL,
	label TEXT,
	disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now')),
	last_used_at TEXT,
	rotated_at TEXT
);

CREATE TABLE IF NOT EXISTS relay_events (
	id TEXT PRIMARY KEY,
	ha_install_id TEXT NOT NULL,
	event_type TEXT NOT NULL CHECK (event_type IN ('ask_dj_response', 'ask_dj_confirm', 'playback_change')),
	client_type TEXT CHECK (client_type IS NULL OR client_type IN ('ios', 'macos', 'watchos')),
	target_count INTEGER NOT NULL DEFAULT 0,
	success_count INTEGER NOT NULL DEFAULT 0,
	error_count INTEGER NOT NULL DEFAULT 0,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`;
