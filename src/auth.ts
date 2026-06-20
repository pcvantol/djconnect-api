import { timingSafeEqualString } from "./crypto";
import { HttpError } from "./http";
import { findInstallTokenByBearer, markInstallTokenUsed } from "./repository";
import type { AppEnv } from "./types";

export async function requireBootstrapAuth(request: Request, env: AppEnv): Promise<void> {
	const authorization = request.headers.get("authorization") ?? "";
	const expected = env.DJCONNECT_RELAY_SECRET;

	if (!expected) {
		throw new HttpError(500, "relay_secret_not_configured");
	}

	if (authorization.startsWith("Bearer ")) {
		const token = authorization.slice("Bearer ".length).trim();
		if (token && (await timingSafeEqualString(token, expected))) {
			return;
		}
	}

	const hmacHeader = request.headers.get("x-djconnect-signature");
	const timestamp = request.headers.get("x-djconnect-timestamp");
	if (hmacHeader && timestamp) {
		const body = await request.clone().arrayBuffer();
		const valid = await verifyHmac(body, timestamp, hmacHeader, expected);
		if (valid) {
			return;
		}
	}

	throw new HttpError(401, "auth_required");
}

export async function requireInstallAuth(request: Request, env: AppEnv, haInstallId: string): Promise<void> {
	const authorization = request.headers.get("authorization") ?? "";
	if (!authorization.startsWith("Bearer ")) {
		throw new HttpError(401, "install_auth_required");
	}

	const token = authorization.slice("Bearer ".length).trim();
	if (!token) {
		throw new HttpError(401, "install_auth_required");
	}

	const record = await findInstallTokenByBearer(env.DB, token);
	if (!record) {
		throw new HttpError(401, "install_auth_required");
	}

	if (!(await timingSafeEqualString(record.ha_install_id, haInstallId))) {
		throw new HttpError(403, "install_token_scope_mismatch");
	}

	await markInstallTokenUsed(env.DB, record.id);
}

async function verifyHmac(
	body: ArrayBuffer,
	timestamp: string,
	header: string,
	secret: string,
): Promise<boolean> {
	const timestampMs = Number(timestamp) * 1000;
	if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > 5 * 60 * 1000) {
		return false;
	}

	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const payload = new Uint8Array(new TextEncoder().encode(`${timestamp}.`).length + body.byteLength);
	payload.set(new TextEncoder().encode(`${timestamp}.`), 0);
	payload.set(new Uint8Array(body), new TextEncoder().encode(`${timestamp}.`).length);
	const signature = await crypto.subtle.sign("HMAC", key, payload);
	const expected = [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
	const supplied = header.startsWith("sha256=") ? header.slice("sha256=".length) : header;
	return timingSafeEqualString(supplied, expected);
}
