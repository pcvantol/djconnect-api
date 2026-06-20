import { requireBootstrapAuth, requireInstallAuth } from "./auth";
import { buildApnsPayload, isInvalidTokenReason, sendApns } from "./apns";
import { sha256Hex } from "./crypto";
import { HttpError, json, readJson } from "./http";
import { auditEvent, findActiveRegistrations, issueInstallToken, markRegistrationError, markRegistrationSuccess, rotateInstallToken, unregister, upsertRegistration } from "./repository";
import type { AppEnv, InstallTokenRequest, PushEventRequest, RegisterRequest, RotateInstallTokenRequest, UnregisterRequest } from "./types";

const VALID_CLIENT_TYPES = new Set(["ios", "macos", "watchos"]);
const VALID_ENVIRONMENTS = new Set(["sandbox", "production"]);
const VALID_EVENTS = new Set(["ask_dj_response", "ask_dj_confirm", "playback_change"]);

export default {
	async fetch(request, env, ctx): Promise<Response> {
		try {
			return await route(request, env as AppEnv, ctx);
		} catch (error) {
			if (error instanceof HttpError) {
				return json({ error: error.code }, { status: error.status });
			}
			console.error(JSON.stringify({ level: "error", message: "unhandled_error" }));
			return json({ error: "internal_error" }, { status: 500 });
		}
	},
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: AppEnv, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);
	if (request.method === "GET" && url.pathname === "/health") {
		return json({ ok: true, service: "djconnect-api" });
	}

	if (request.method === "POST" && url.pathname === "/v1/install/token") {
		await requireBootstrapAuth(request, env);
		const input = await readJson<InstallTokenRequest>(request);
		validateInstallTokenRequest(input);
		const result = await issueInstallToken(env.DB, input);
		return json({ ok: true, id: result.id, token: result.token, token_hash: result.tokenHash });
	}

	if (request.method === "POST" && url.pathname === "/v1/install/rotate") {
		const input = await readJson<RotateInstallTokenRequest>(request);
		requireBearerHeader(request);
		validateRotateInstallToken(input);
		await requireInstallAuth(request, env, input.ha_install_id);
		const result = await rotateInstallToken(env.DB, input);
		return json({ ok: true, id: result.id, token: result.token, token_hash: result.tokenHash });
	}

	if (request.method === "POST" && url.pathname === "/v1/push/register") {
		const input = await readJson<RegisterRequest>(request);
		requireBearerHeader(request);
		validateRegister(input);
		await requireInstallAuth(request, env, input.ha_install_id);
		const result = await upsertRegistration(env.DB, env, input);
		return json({ ok: true, id: result.id, apns_token_hash: result.tokenHash });
	}

	if (request.method === "POST" && url.pathname === "/v1/push/unregister") {
		const input = await readJson<UnregisterRequest>(request);
		requireBearerHeader(request);
		validateUnregister(input);
		await requireInstallAuth(request, env, input.ha_install_id);
		const changes = await unregister(env.DB, input);
		return json({ ok: true, disabled: changes });
	}

	if (request.method === "POST" && url.pathname === "/v1/push/event") {
		const input = await readJson<PushEventRequest>(request);
		requireBearerHeader(request);
		validatePushEvent(input);
		await requireInstallAuth(request, env, input.ha_install_id);
		const registrations = await findActiveRegistrations(env.DB, input);
		const payload = buildApnsPayload(input);
		let delivered = 0;
		let failed = 0;

		for (const registration of registrations) {
			const result = await sendApns(env, registration, payload);
			if (result.ok) {
				delivered += 1;
				await markRegistrationSuccess(env.DB, registration.id);
			} else {
				failed += 1;
				await markRegistrationError(
					env.DB,
					registration.id,
					result.reason ?? `HTTP_${result.status}`,
					isInvalidTokenReason(result.status, result.reason),
				);
			}
		}

		ctx.waitUntil(auditEvent(env.DB, {
			ha_install_id: input.ha_install_id,
			event_type: input.event_type,
			client_type: input.client_types?.length === 1 ? input.client_types[0] : undefined,
			target: registrations.length,
			success: delivered,
			error: failed,
		}));
		return json({ ok: true, matched: registrations.length, delivered, failed });
	}

	return json({ error: "not_found" }, { status: 404 });
}

function requireBearerHeader(request: Request): void {
	const authorization = request.headers.get("authorization") ?? "";
	if (!authorization.startsWith("Bearer ") || authorization.slice("Bearer ".length).trim() === "") {
		throw new HttpError(401, "install_auth_required");
	}
}

function validateInstallTokenRequest(input: InstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	if (input.ha_user_hash !== undefined && typeof input.ha_user_hash !== "string") {
		throw new HttpError(400, "invalid_ha_user_hash");
	}
	if (input.label !== undefined && typeof input.label !== "string") {
		throw new HttpError(400, "invalid_label");
	}
}

function validateRotateInstallToken(input: RotateInstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
}

function validateRegister(input: RegisterRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.device_id, "device_id");
	requireString(input.apns_token, "apns_token");
	if (!VALID_CLIENT_TYPES.has(input.client_type)) {
		throw new HttpError(400, "invalid_client_type");
	}
	if (input.apns_environment && !VALID_ENVIRONMENTS.has(input.apns_environment)) {
		throw new HttpError(400, "invalid_apns_environment");
	}
}

function validateUnregister(input: UnregisterRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.device_id, "device_id");
	if (input.client_type && !VALID_CLIENT_TYPES.has(input.client_type)) {
		throw new HttpError(400, "invalid_client_type");
	}
}

function validatePushEvent(input: PushEventRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	if (!VALID_EVENTS.has(input.event_type)) {
		throw new HttpError(400, "invalid_event_type");
	}
	for (const clientType of input.client_types ?? []) {
		if (!VALID_CLIENT_TYPES.has(clientType)) {
			throw new HttpError(400, "invalid_client_type");
		}
	}
}

function requireString(value: unknown, field: string): void {
	if (typeof value !== "string" || value.trim() === "") {
		throw new HttpError(400, `missing_${field}`);
	}
}

export async function tokenHashForTest(token: string): Promise<string> {
	return sha256Hex(token);
}
