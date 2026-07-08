import { HttpError } from "./http";
import type { ApiMessageKey } from "./messages";
import type { AdminDiagnosticsQuery, AdminRegistrationsQuery, BootstrapProofRequest, InstallTokenRequest, PushEventRequest, RegisterRequest, RevokeInstallTokenRequest, RotateInstallTokenRequest, UnregisterRequest } from "./types";

type RequiredStringField = "apns_token" | "bootstrap_proof" | "device_id" | "ha_install_id" | "pairing_session_id" | "token_id";
type MissingStringKey = `missing_${RequiredStringField}`;

const VALID_CLIENT_TYPES = new Set(["ios", "macos", "watchos"]);
const VALID_ENVIRONMENTS = new Set(["sandbox", "production"]);
const VALID_EVENTS = new Set(["ask_dj_response", "ask_dj_confirm"]);
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

export function requireBearerHeader(request: Request): void {
	const authorization = request.headers.get("authorization") ?? "";
	if (!authorization.startsWith("Bearer ") || authorization.slice("Bearer ".length).trim() === "") {
		throw new HttpError(401, "install_auth_required");
	}
}

export function validateInstallTokenRequest(input: InstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.bootstrap_proof, "bootstrap_proof");
	requireString(input.device_id, "device_id");
	if (!VALID_CLIENT_TYPES.has(input.client_type ?? "")) {
		throw new HttpError(400, "invalid_client_type");
	}
	if (input.ha_user_hash !== undefined && typeof input.ha_user_hash !== "string") {
		throw new HttpError(400, "invalid_ha_user_hash");
	}
	if (input.label !== undefined && typeof input.label !== "string") {
		throw new HttpError(400, "invalid_label");
	}
}

export function validateBootstrapProofRequest(input: BootstrapProofRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.device_id, "device_id");
	if (!VALID_CLIENT_TYPES.has(input.client_type)) {
		throw new HttpError(400, "invalid_client_type");
	}
	if (input.ttl_seconds !== undefined && (!Number.isInteger(input.ttl_seconds) || input.ttl_seconds < 60 || input.ttl_seconds > 600)) {
		throw new HttpError(400, "invalid_ttl_seconds");
	}
}

export function validatePairingBootstrapProofRequest(input: BootstrapProofRequest): void {
	validateBootstrapProofRequest(input);
	requireString(input.pairing_session_id, "pairing_session_id");
}

export function validateRotateInstallToken(input: RotateInstallTokenRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
}

export function validateRevokeInstallToken(input: RevokeInstallTokenRequest): void {
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

export function validateRegister(input: RegisterRequest): void {
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

export function validateUnregister(input: UnregisterRequest): void {
	requireString(input.ha_install_id, "ha_install_id");
	requireString(input.device_id, "device_id");
	if (input.client_type && !VALID_CLIENT_TYPES.has(input.client_type)) {
		throw new HttpError(400, "invalid_client_type");
	}
}

export function validatePushEvent(input: PushEventRequest): void {
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

export function validateAdminRegistrationsQuery(url: URL): AdminRegistrationsQuery {
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

export function validateAdminDiagnosticsQuery(url: URL): AdminDiagnosticsQuery {
	return {
		since_hours: clampNumber(url.searchParams.get("since_hours"), 24, 1, 24 * 30),
	};
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

function clampNumber(value: string | null, fallback: number, min: number, max: number): number {
	if (value === null || value.trim() === "") return fallback;
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
		throw new HttpError(400, "invalid_pagination");
	}
	return parsed;
}

function optionalEnum(value: string | null, allowed: Set<string>, errorCode: ApiMessageKey): string | undefined {
	if (value === null || value.trim() === "") return undefined;
	if (!allowed.has(value)) {
		throw new HttpError(400, errorCode);
	}
	return value;
}

function optionalBoolean(value: string | null, errorCode: ApiMessageKey): boolean | undefined {
	if (value === null || value.trim() === "") return undefined;
	if (value === "true" || value === "1") return true;
	if (value === "false" || value === "0") return false;
	throw new HttpError(400, errorCode);
}

function requireString(value: unknown, field: RequiredStringField): void {
	if (typeof value !== "string" || value.trim() === "") {
		throw new HttpError(400, `missing_${field}` satisfies MissingStringKey);
	}
}
