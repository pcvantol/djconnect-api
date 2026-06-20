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

	it("accepts valid HMAC bootstrap auth and rejects stale HMAC timestamps", async () => {
		const body = {
			ha_install_id: "example-ha-install",
			ha_user_hash: "example-user-hash",
			label: "example-ha-hmac",
		};
		const validResponse = await dispatchWithHeaders(
			"/v1/install/token",
			body,
			await hmacHeaders(body, Math.floor(Date.now() / 1000)),
		);
		expect(validResponse.status).toBe(200);

		const staleResponse = await dispatchWithHeaders(
			"/v1/install/token",
			body,
			await hmacHeaders(body, Math.floor(Date.now() / 1000) - 10 * 60),
		);
		expect(staleResponse.status).toBe(401);
		expect(await staleResponse.json()).toEqual({ error: "auth_required" });
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

	it("filters push delivery by ha_user_hash", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		await registerDevice(installAuth, {
			device_id: "example-device-user-a",
			ha_user_hash: "example-user-hash-a",
			apns_token: "example-apns-token-user-a",
		});
		await registerDevice(installAuth, {
			device_id: "example-device-user-b",
			ha_user_hash: "example-user-hash-b",
			apns_token: "example-apns-token-user-b",
		});
		const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));

		const event = await dispatch("/v1/push/event", {
			ha_install_id: "example-ha-install",
			ha_user_hash: "example-user-hash-b",
			event_type: "ask_dj_response",
		}, installAuth);
		const body = await event.json() as { matched: number; delivered: number; failed: number };

		expect(event.status).toBe(200);
		expect(body).toMatchObject({ matched: 1, delivered: 1, failed: 0 });
		expect(fetchMock).toHaveBeenCalledOnce();
		expect(fetchMock.mock.calls[0]?.[0]).toBe("https://api.sandbox.push.apple.com/3/device/example-apns-token-user-b");
	});

	it("selects topics for multiple client types", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		await registerDevice(installAuth, {
			device_id: "example-ios-device",
			client_type: "ios",
			apns_token: "example-ios-apns-token",
			apns_environment: "production",
		});
		await registerDevice(installAuth, {
			device_id: "example-macos-device",
			client_type: "macos",
			apns_token: "example-macos-apns-token",
			apns_environment: "production",
		});
		await registerDevice(installAuth, {
			device_id: "example-watchos-device",
			client_type: "watchos",
			apns_token: "example-watchos-apns-token",
			apns_environment: "production",
		});
		const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("{}", { status: 200 }));

		const event = await dispatch("/v1/push/event", {
			ha_install_id: "example-ha-install",
			event_type: "playback_change",
			client_types: ["ios", "watchos"],
		}, installAuth);
		const body = await event.json() as { matched: number; delivered: number; failed: number };

		expect(event.status).toBe(200);
		expect(body).toMatchObject({ matched: 2, delivered: 2, failed: 0 });
		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(fetchMock.mock.calls.map((call) => call[0])).toEqual([
			"https://api.push.apple.com/3/device/example-ios-apns-token",
			"https://api.push.apple.com/3/device/example-watchos-apns-token",
		]);
		expect(fetchMock.mock.calls.map((call) => (call[1]?.headers as Record<string, string>)["apns-topic"])).toEqual([
			"dev.djconnect.ios",
			"dev.djconnect.watch",
		]);
	});

	it("audits mixed APNs success and failure counts", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		await registerDevice(installAuth, {
			device_id: "example-success-device",
			apns_token: "example-success-apns-token",
		});
		await registerDevice(installAuth, {
			device_id: "example-server-error-device",
			apns_token: "example-server-error-apns-token",
		});
		await registerDevice(installAuth, {
			device_id: "example-invalid-device",
			apns_token: "example-invalid-apns-token",
		});
		vi.spyOn(globalThis, "fetch").mockImplementation(async (url) => {
			const endpoint = String(url);
			if (endpoint.endsWith("/example-success-apns-token")) {
				return new Response("{}", { status: 200 });
			}
			if (endpoint.endsWith("/example-invalid-apns-token")) {
				return new Response(JSON.stringify({ reason: "Unregistered" }), { status: 410 });
			}
			return new Response(JSON.stringify({ reason: "InternalServerError" }), { status: 500 });
		});

		const event = await dispatch("/v1/push/event", {
			ha_install_id: "example-ha-install",
			event_type: "ask_dj_response",
		}, installAuth);
		const body = await event.json() as { matched: number; delivered: number; failed: number };

		expect(event.status).toBe(200);
		expect(body).toMatchObject({ matched: 3, delivered: 1, failed: 2 });
		const audit = await env.DB.prepare(`
			SELECT target_count, success_count, error_count, client_type
			FROM relay_events
			WHERE ha_install_id = ?
		`).bind("example-ha-install").first<{
			target_count: number;
			success_count: number;
			error_count: number;
			client_type: string | null;
		}>();
		expect(audit).toEqual({ target_count: 3, success_count: 1, error_count: 2, client_type: null });

		const invalid = await env.DB.prepare(`
			SELECT disabled, invalid, last_error_code
			FROM registrations
			WHERE device_id = ?
		`).bind("example-invalid-device").first<{ disabled: number; invalid: number; last_error_code: string }>();
		expect(invalid).toEqual({ disabled: 1, invalid: 1, last_error_code: "Unregistered" });
	});

	it("lists admin registrations with operator auth and privacy-safe fields", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");
		const register = await dispatch("/v1/push/register", registerPayload(), installAuth);
		expect(register.status).toBe(200);
		await env.DB.prepare("UPDATE registrations SET last_success_at = datetime('now') WHERE device_id = ?").bind("example-device").run();

		const response = await dispatchGet("/v1/admin/registrations?limit=10", AUTH);
		expect(response.status).toBe(200);
		const body = await response.json() as {
			ok: boolean;
			registrations: Array<Record<string, unknown>>;
			next_offset: number | null;
		};
		expect(body.ok).toBe(true);
		expect(body.next_offset).toBeNull();
		expect(body.registrations).toHaveLength(1);

		const row = body.registrations[0]!;
		expect(row.id).toEqual(expect.any(String));
		expect(row.ha_install_id_hash).toMatch(/^[a-f0-9]{16}$/);
		expect(row.ha_install_id_hash).not.toBe("example-ha-install");
		expect(row.device_id_hash).toMatch(/^[a-f0-9]{16}$/);
		expect(row.device_id_hash).not.toBe("example-device");
		expect(row.ha_user_hash).toBe("example-user-hash");
		expect(row.client_type).toBe("ios");
		expect(row.apns_environment).toBe("sandbox");
		expect(row.topic).toBe("dev.djconnect.ios");
		expect(row.app_bundle_id).toBe("dev.djconnect.ios");
		expect(row.app_version).toBe("1.0.0");
		expect(row.locale).toBe("nl-NL");
		expect(row.categories).toEqual(["ask_dj"]);
		expect(row.disabled).toBe(false);
		expect(row.invalid).toBe(false);
		expect(row.apns_token_hash_prefix).toMatch(/^[a-f0-9]{12}$/);
		expect(row.created_at).toEqual(expect.any(String));
		expect(row.updated_at).toEqual(expect.any(String));
		expect(row.last_success_at).toEqual(expect.any(String));
		expect(row.last_error_code).toBeNull();

		const serialized = JSON.stringify(body);
		expect(serialized).not.toContain("example-apns-token");
		expect(serialized).not.toContain("apns_token_ciphertext");
		expect(serialized).not.toContain("apns_token_nonce");
		expect(serialized).not.toContain("apns_token_key_version");
		expect(serialized).not.toContain("APNS_PRIVATE_KEY");
		expect(serialized).not.toContain("APNS_TOKEN_ENCRYPTION_KEY");
		expect(serialized).not.toContain("DJCONNECT_RELAY_SECRET");
		expect(serialized).not.toContain(EXAMPLE_RELAY_SECRET);
	});

	it("protects admin registrations from anonymous and per-install auth", async () => {
		const installAuth = await issueInstallAuth("example-ha-install");

		const anonymous = await dispatchGet("/v1/admin/registrations");
		expect(anonymous.status).toBe(401);

		const perInstall = await dispatchGet("/v1/admin/registrations", installAuth);
		expect(perInstall.status).toBe(403);
	});

	it("filters and paginates admin registrations", async () => {
		const firstAuth = await issueInstallAuth("example-ha-install");
		const secondAuth = await issueInstallAuth("example-second-install");
		const thirdAuth = await issueInstallAuth("example-third-install");
		await dispatch("/v1/push/register", registerPayload(), firstAuth);
		await dispatch("/v1/push/register", {
			...registerPayload(),
			ha_install_id: "example-second-install",
			device_id: "example-mac-device",
			client_type: "macos",
			apns_environment: "production",
			app_bundle_id: "dev.djconnect.mac",
		}, secondAuth);
		await dispatch("/v1/push/register", {
			...registerPayload(),
			ha_install_id: "example-third-install",
			device_id: "example-watch-device",
			client_type: "watchos",
		}, thirdAuth);
		await env.DB.prepare("UPDATE registrations SET disabled = 1, invalid = 1, last_error_code = 'Unregistered' WHERE device_id = ?").bind("example-watch-device").run();

		const macos = await dispatchGet("/v1/admin/registrations?client_type=macos&apns_environment=production", AUTH);
		expect(macos.status).toBe(200);
		const macosBody = await macos.json() as { registrations: Array<{ client_type: string; apns_environment: string }> };
		expect(macosBody.registrations).toHaveLength(1);
		expect(macosBody.registrations[0]).toMatchObject({ client_type: "macos", apns_environment: "production" });

		const disabled = await dispatchGet("/v1/admin/registrations?disabled=true&invalid=1", AUTH);
		expect(disabled.status).toBe(200);
		const disabledBody = await disabled.json() as { registrations: Array<{ disabled: boolean; invalid: boolean; last_error_code: string }> };
		expect(disabledBody.registrations).toHaveLength(1);
		expect(disabledBody.registrations[0]).toMatchObject({ disabled: true, invalid: true, last_error_code: "Unregistered" });

		const filteredInstall = await dispatchGet("/v1/admin/registrations?ha_install_id=example-ha-install", AUTH);
		expect(filteredInstall.status).toBe(200);
		const filteredInstallBody = await filteredInstall.json() as { registrations: Array<{ ha_install_id_hash: string; device_id_hash: string }> };
		expect(filteredInstallBody.registrations).toHaveLength(1);
		expect(JSON.stringify(filteredInstallBody)).not.toContain("example-ha-install");
		expect(JSON.stringify(filteredInstallBody)).not.toContain("example-device");

		const firstPage = await dispatchGet("/v1/admin/registrations?limit=2&offset=0", AUTH);
		expect(firstPage.status).toBe(200);
		const firstPageBody = await firstPage.json() as { registrations: unknown[]; next_offset: number | null };
		expect(firstPageBody.registrations).toHaveLength(2);
		expect(firstPageBody.next_offset).toBe(2);

		const secondPage = await dispatchGet("/v1/admin/registrations?limit=2&offset=2", AUTH);
		expect(secondPage.status).toBe(200);
		const secondPageBody = await secondPage.json() as { registrations: unknown[]; next_offset: number | null };
		expect(secondPageBody.registrations).toHaveLength(1);
		expect(secondPageBody.next_offset).toBeNull();
	});

	it("selects sandbox and production APNs endpoints", () => {
		expect(apnsEndpoint("sandbox", "abc")).toBe("https://api.sandbox.push.apple.com/3/device/abc");
		expect(apnsEndpoint("production", "abc")).toBe("https://api.push.apple.com/3/device/abc");
	});
});

async function dispatch(path: string, body: unknown, authorization?: string): Promise<Response> {
	return dispatchWithHeaders(path, body, {
		...(authorization ? { authorization } : {}),
	});
}

async function dispatchGet(path: string, authorization?: string): Promise<Response> {
	const request = new IncomingRequest(`https://api.djconnect.dev${path}`, {
		method: "GET",
		headers: {
			...(authorization ? { authorization } : {}),
		},
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, testEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function dispatchWithHeaders(path: string, body: unknown, headers: Record<string, string>): Promise<Response> {
	const serializedBody = JSON.stringify(body);
	const request = new IncomingRequest(`https://api.djconnect.dev${path}`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			...headers,
		},
		body: serializedBody,
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, testEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function hmacHeaders(body: unknown, timestamp: number): Promise<Record<string, string>> {
	const serializedBody = JSON.stringify(body);
	const payload = `${timestamp}.${serializedBody}`;
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(EXAMPLE_RELAY_SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
	const signatureHex = [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
	return {
		"x-djconnect-timestamp": String(timestamp),
		"x-djconnect-signature": `sha256=${signatureHex}`,
	};
}

async function issueInstallAuth(haInstallId: string): Promise<string> {
	const response = await dispatch("/v1/install/token", { ha_install_id: haInstallId }, AUTH);
	expect(response.status).toBe(200);
	const body = await response.json() as { token: string };
	return `Bearer ${body.token}`;
}

async function registerDevice(installAuth: string, overrides: Partial<ReturnType<typeof registerPayload>> = {}): Promise<void> {
	const response = await dispatch("/v1/push/register", registerPayload(overrides), installAuth);
	expect(response.status).toBe(200);
}

function registerPayload(overrides: Partial<{
	ha_install_id: string;
	ha_user_hash: string;
	device_id: string;
	client_type: "ios" | "macos" | "watchos";
	apns_token: string;
	apns_environment: "sandbox" | "production";
	app_bundle_id: string;
	app_version: string;
	locale: string;
	categories: string[];
}> = {}) {
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
		...overrides,
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
