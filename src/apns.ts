import { base64Url, decryptSecret } from "./crypto";
import { notificationText, resolveSupportedLanguage, type SupportedLanguage } from "./messages";
import type { ApnsEnvironment, ApnsResult, AppEnv, EventType, Registration } from "./types";

export type Fetcher = typeof fetch;

const APNS_HOSTS: Record<ApnsEnvironment, string> = {
	sandbox: "https://api.sandbox.push.apple.com",
	production: "https://api.push.apple.com",
};

export function apnsEndpoint(environment: ApnsEnvironment, token: string): string {
	return `${APNS_HOSTS[environment]}/3/device/${token}`;
}

export function buildApnsPayload(input: {
	event_type: EventType;
	history_revision?: string | number;
	client_message_id?: string;
	open_target?: string;
	locale?: string | null;
	language?: SupportedLanguage;
}): Record<string, unknown> {
	const alert = notificationText(input.event_type, input.language ?? resolveSupportedLanguage(input.locale));
	return {
		aps: {
			alert,
			sound: "default",
			"thread-id": "ask-dj",
			"interruption-level": "active",
		},
		event_type: input.event_type,
		history_revision: input.history_revision == null ? undefined : String(input.history_revision),
		client_message_id: input.client_message_id,
		open_target: input.open_target ?? "ask_dj",
	};
}

export function isInvalidTokenReason(status: number, reason?: string): boolean {
	return status === 410 || reason === "BadDeviceToken" || reason === "Unregistered";
}

export async function sendApns(
	env: AppEnv,
	registration: Registration,
	payload: Record<string, unknown>,
	fetcher: Fetcher = fetch,
): Promise<ApnsResult> {
	let deviceToken: string | null;
	try {
		deviceToken = await registrationApnsToken(env, registration);
	} catch {
		return { ok: false, status: 0, reason: "TokenDecryptFailed", endpoint: "" };
	}

	if (!deviceToken) {
		return { ok: false, status: 0, reason: "MissingDeviceToken", endpoint: "" };
	}

	const endpoint = apnsEndpoint(registration.apns_environment, deviceToken);
	if (env.DJCONNECT_SMOKE_TEST_MODE === "enabled" && deviceToken.startsWith("example-")) {
		return { ok: true, status: 200, endpoint };
	}

	const token = await createProviderToken(env);
	const response = await fetcher(endpoint, {
		method: "POST",
		headers: {
			authorization: `bearer ${token}`,
			"apns-topic": registration.topic,
			"apns-push-type": "alert",
			"content-type": "application/json",
		},
		body: JSON.stringify(payload),
	});

	let reason: string | undefined;
	if (!response.ok) {
		const body = (await response.json().catch(() => undefined)) as { reason?: string } | undefined;
		reason = body?.reason ?? `HTTP_${response.status}`;
	}

	return { ok: response.ok, status: response.status, reason, endpoint };
}

async function registrationApnsToken(env: AppEnv, registration: Registration): Promise<string | null> {
	if (registration.apns_token_ciphertext && registration.apns_token_nonce) {
		return decryptSecret(registration.apns_token_ciphertext, registration.apns_token_nonce, env.APNS_TOKEN_ENCRYPTION_KEY);
	}

	return registration.apns_token;
}

async function createProviderToken(env: AppEnv): Promise<string> {
	const header = base64Url(JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID }));
	const claims = base64Url(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: Math.floor(Date.now() / 1000) }));
	const signingInput = `${header}.${claims}`;
	const key = await importPrivateKey(env.APNS_PRIVATE_KEY);
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		key,
		new TextEncoder().encode(signingInput),
	);
	return `${signingInput}.${base64Url(derToJose(new Uint8Array(signature)))}`;
}

async function importPrivateKey(pem: string): Promise<CryptoKey> {
	const body = pem.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s/g, "");
	const binary = atob(body);
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}
	return crypto.subtle.importKey(
		"pkcs8",
		bytes,
		{ name: "ECDSA", namedCurve: "P-256" },
		false,
		["sign"],
	);
}

function derToJose(signature: Uint8Array): ArrayBuffer {
	if (signature.byteLength === 64) {
		return new Uint8Array(signature).buffer;
	}

	// Workers Web Crypto returns raw ECDSA P-256 signatures today. This fallback keeps
	// APNs JWT formatting correct if a DER encoded signature appears in tests/runtimes.
	let offset = 3;
	let rLength = signature[offset++];
	if (rLength > 32) offset += rLength - 32;
	const r = signature.slice(offset, offset + Math.min(rLength, 32));
	offset += Math.min(rLength, 32) + 1;
	let sLength = signature[offset++];
	if (sLength > 32) offset += sLength - 32;
	const s = signature.slice(offset, offset + Math.min(sLength, 32));
	const jose = new Uint8Array(64);
	jose.set(r, 32 - r.length);
	jose.set(s, 64 - s.length);
	return jose.buffer;
}
