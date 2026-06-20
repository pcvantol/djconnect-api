import { timingSafeEqualString } from "./crypto";
import { HttpError } from "./http";
import type { AppEnv } from "./types";

export async function requireRelayAuth(request: Request, env: AppEnv): Promise<void> {
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
