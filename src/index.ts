import { requireAdminAuth, requireBootstrapAuth, requireInstallAuth } from "./auth";
import { buildApnsPayload, isInvalidTokenReason, sendApns } from "./apns";
import { sha256Hex } from "./crypto";
import { HttpError, json, readJson } from "./http";
import { auditEvent, consumeBootstrapProof, enforceBootstrapRateLimit, findActiveRegistrations, issueBootstrapProof, issueInstallToken, listAdminRegistrations, markRegistrationError, markRegistrationSuccess, revokeInstallToken, rotateInstallToken, unregister, upsertRegistration } from "./repository";
import type { AdminRegistrationsQuery, AppEnv, BootstrapProofRequest, InstallTokenRequest, PushEventRequest, RegisterRequest, RevokeInstallTokenRequest, RotateInstallTokenRequest, UnregisterRequest } from "./types";

const VALID_CLIENT_TYPES = new Set(["ios", "macos", "watchos"]);
const VALID_BOOTSTRAP_CLIENT_TYPES = new Set(["ios", "macos", "watchos", "raspberry_pi", "esp32", "conversation_agent"]);
const VALID_ENVIRONMENTS = new Set(["sandbox", "production"]);
const VALID_EVENTS = new Set(["ask_dj_response", "ask_dj_confirm", "playback_change"]);
const FORBIDDEN_PAYLOAD_KEYS = new Set([
	"prompt",
	"raw_prompt",
	"assistant_response",
	"response",
	"response_text",
	"history",
	"chat_history",
	"memory",
	"apns_token",
	"ha_token",
	"spotify_token",
	"token",
	"secret",
	"authorization",
]);

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

	if (request.method === "GET" && url.pathname === "/v1/admin/registrations") {
		await requireAdminAuth(request, env);
		const result = await listAdminRegistrations(env.DB, validateAdminRegistrationsQuery(url));
		return json({ ok: true, ...result });
	}

	if (request.method === "POST" && url.pathname === "/v1/operator/install-token/revoke") {
		await requireAdminAuth(request, env);
		const input = await readJson<RevokeInstallTokenRequest>(request);
		validateRevokeInstallToken(input);
		const result = await revokeInstallToken(env.DB, input);
		return json({ ok: true, revoked: result.revoked });
	}

	if (request.method === "POST" && url.pathname === "/v1/install/bootstrap-proof") {
		await requireAdminAuth(request, env);
		const input = await readJson<BootstrapProofRequest>(request);
		validateBootstrapProofRequest(input);
		const result = await issueBootstrapProof(env.DB, input);
		return json({ ok: true, id: result.id, bootstrap_proof: result.proof, proof_hash: result.proofHash, expires_at: result.expiresAt });
	}

	if (request.method === "POST" && url.pathname === "/v1/install/token") {
		const input = await readJson<InstallTokenRequest>(request);
		validateInstallTokenRequest(input);
		await enforceBootstrapRateLimit(env.DB, {
			ip: clientIp(request),
			ha_install_id: input.ha_install_id,
			device_id: input.device_id!,
		});
		await consumeBootstrapProof(env.DB, input);
		const result = await issueInstallToken(env.DB, input);
		return json({
			ok: true,
			success: true,
			id: result.id,
			token: result.token,
			install_token: result.token,
			token_hash: result.tokenHash,
			expires_at: null,
		});
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

function clientIp(request: Request): string {
	return request.headers.get("cf-connecting-ip")
		?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
		?? "unknown";
}

function requireBearerHeader(request: Request): void {
	const authorization = request.headers.get("authorization") ?? "";
	if (!authorization.startsWith("Bearer ") || authorization.slice("Bearer ".length).trim() === "") {
		throw new HttpError(401, "install_auth_required");
	}
}

function validateInstallTokenRequest(input: InstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.bootstrap_proof, "bootstrap_proof");
	requireString(input.device_id, "device_id");
	if (!VALID_BOOTSTRAP_CLIENT_TYPES.has(input.client_type ?? "")) {
		throw new HttpError(400, "invalid_client_type");
	}
	if (input.ha_user_hash !== undefined && typeof input.ha_user_hash !== "string") {
		throw new HttpError(400, "invalid_ha_user_hash");
	}
	if (input.label !== undefined && typeof input.label !== "string") {
		throw new HttpError(400, "invalid_label");
	}
}

function validateBootstrapProofRequest(input: BootstrapProofRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.device_id, "device_id");
	if (!VALID_BOOTSTRAP_CLIENT_TYPES.has(input.client_type)) {
		throw new HttpError(400, "invalid_client_type");
	}
	if (input.ttl_seconds !== undefined && (!Number.isInteger(input.ttl_seconds) || input.ttl_seconds < 60 || input.ttl_seconds > 600)) {
		throw new HttpError(400, "invalid_ttl_seconds");
	}
}

function validateRotateInstallToken(input: RotateInstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
}

function validateRevokeInstallToken(input: RevokeInstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.token_id, "token_id");
	if (input.reason !== undefined) {
		if (typeof input.reason !== "string") {
			throw new HttpError(400, "invalid_reason");
		}
		if (input.reason.length > 200) {
			throw new HttpError(400, "invalid_reason");
		}
		if (/\bdjci_[A-Za-z0-9_-]+/.test(input.reason)) {
			throw new HttpError(400, "unsafe_payload");
		}
		rejectForbiddenPayloadKeys({ reason: input.reason });
	}
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
	rejectForbiddenPayloadKeys(input);
	if (!VALID_EVENTS.has(input.event_type)) {
		throw new HttpError(400, "invalid_event_type");
	}
	for (const clientType of input.client_types ?? []) {
		if (!VALID_CLIENT_TYPES.has(clientType)) {
			throw new HttpError(400, "invalid_client_type");
		}
	}
}

function rejectForbiddenPayloadKeys(value: unknown): void {
	if (value === null || typeof value !== "object") return;
	for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
		const normalized = key.toLowerCase();
		if (FORBIDDEN_PAYLOAD_KEYS.has(normalized)) {
			throw new HttpError(400, "unsafe_payload");
		}
		if (Array.isArray(child)) {
			for (const item of child) rejectForbiddenPayloadKeys(item);
		} else {
			rejectForbiddenPayloadKeys(child);
		}
	}
}

function validateAdminRegistrationsQuery(url: URL): AdminRegistrationsQuery {
	const params = url.searchParams;
	const limit = clampNumber(params.get("limit"), 50, 1, 100);
	const offset = clampNumber(params.get("offset") ?? params.get("cursor"), 0, 0, 100000);
	const clientType = optionalEnum(params.get("client_type"), VALID_CLIENT_TYPES, "invalid_client_type");
	const apnsEnvironment = optionalEnum(params.get("apns_environment"), VALID_ENVIRONMENTS, "invalid_apns_environment");
	const disabled = optionalBoolean(params.get("disabled"), "invalid_disabled");
	const invalid = optionalBoolean(params.get("invalid"), "invalid_invalid");
	const haInstallId = params.get("ha_install_id")?.trim() || undefined;
	return {
		limit,
		offset,
		...(clientType ? { client_type: clientType as AdminRegistrationsQuery["client_type"] } : {}),
		...(apnsEnvironment ? { apns_environment: apnsEnvironment as AdminRegistrationsQuery["apns_environment"] } : {}),
		...(disabled !== undefined ? { disabled } : {}),
		...(invalid !== undefined ? { invalid } : {}),
		...(haInstallId ? { ha_install_id: haInstallId } : {}),
	};
}

function clampNumber(value: string | null, fallback: number, min: number, max: number): number {
	if (value === null || value.trim() === "") return fallback;
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
		throw new HttpError(400, "invalid_pagination");
	}
	return parsed;
}

function optionalEnum(value: string | null, allowed: Set<string>, errorCode: string): string | undefined {
	if (value === null || value.trim() === "") return undefined;
	if (!allowed.has(value)) {
		throw new HttpError(400, errorCode);
	}
	return value;
}

function optionalBoolean(value: string | null, errorCode: string): boolean | undefined {
	if (value === null || value.trim() === "") return undefined;
	if (value === "true" || value === "1") return true;
	if (value === "false" || value === "0") return false;
	throw new HttpError(400, errorCode);
}

function requireString(value: unknown, field: string): void {
	if (typeof value !== "string" || value.trim() === "") {
		throw new HttpError(400, `missing_${field}`);
	}
}

export async function tokenHashForTest(token: string): Promise<string> {
	return sha256Hex(token);
}
