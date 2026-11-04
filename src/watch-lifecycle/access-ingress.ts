import { createWatchAccessKeyResolver } from "./access-jwks";
import { parseStrictJson } from "../surface-push/wire";
import { decodeLifecycleClaims } from "./proof";
import { readSignedWatchRequest } from "./signed-http";

type PreferenceAction = "preference-read" | "preference-write";
export type WatchMachineContext = Readonly<{
	installation: string;
	credentialId: string;
	credentialGeneration: number;
	action: PreferenceAction;
	expiresAt: number;
	submitBeforeMs: number;
}>;

interface WatchPreferenceBinding {
	preference(context: WatchMachineContext, body: Uint8Array, proof: Uint8Array): Promise<Response>;
}

interface WatchAccessConfiguration {
	endpoint: string;
	issuer: string;
	accessAudience: string;
	lifecycleAudience: string;
	installation: string;
	credentialId: string;
	credentialGeneration: number;
	maxAssertionAgeSeconds: number;
	/** Only use signing keys from the configured issuer, indexed by key ID. */
	resolveVerificationKey?(kid: string, signal: AbortSignal): Promise<CryptoKey | null>;
}

const unavailable = () => Response.json({ error: "watch_preference_unavailable" }, {
	status: 403, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
});
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function decodeSegment(segment: string): Uint8Array<ArrayBuffer> {
	if (!/^[A-Za-z0-9_-]+$/.test(segment)) throw new TypeError("invalid JWT segment");
	const raw = atob(segment.replace(/-/g, "+").replace(/_/g, "/"));
	if (btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") !== segment) {
		throw new TypeError("noncanonical JWT segment");
	}
	return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function decodeObject(segment: string): Record<string, unknown> {
	const value = parseStrictJson(decoder.decode(decodeSegment(segment)));
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("invalid JWT object");
	return value as Record<string, unknown>;
}

/** Separate HA-dev HTTPS ingress. The named internal binding owns pairing and currentness. */
export function createWatchAccessIngress(
	config?: WatchAccessConfiguration, binding?: WatchPreferenceBinding,
) {
	const policy = config && Object.freeze({
		...config,
		resolveVerificationKey: config.resolveVerificationKey ?? createWatchAccessKeyResolver(config.issuer),
	});
	return async (request: Request, ctx: Pick<ExecutionContext, "access">): Promise<Response> => {
		if (!policy || !binding || !ctx.access || request.url !== policy.endpoint ||
			new URL(request.url).protocol !== "https:" || request.method !== "POST" ||
			request.headers.has("cookie") || request.headers.has("content-encoding") ||
			request.headers.get("content-type")?.trim().toLowerCase() !== "application/json") return unavailable();

		let writeForwarded = false;
		try {
			const submitBeforeMs = Date.now() + 3000;
			const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
			const token = request.headers.get("cf-access-jwt-assertion");
			if (!token || token.length > 8192) return unavailable();
			const segments = token.split(".");
			if (segments.length !== 3) return unavailable();
			const [header, payload, signature] = segments;
			const { alg, kid, crit } = decodeObject(header);
			if (alg !== "RS256" || crit !== undefined || typeof kid !== "string" ||
				!/^[A-Za-z0-9_-]{1,128}$/.test(kid)) return unavailable();
			const claims = decodeObject(payload);
			const { iss, aud, common_name, type, sub, exp, iat } = claims;
			if (iss !== policy.issuer || !Array.isArray(aud) || aud.length !== 1 ||
				aud[0] !== policy.accessAudience || common_name !== policy.credentialId ||
				type !== "app" || sub !== "" || typeof exp !== "number" || typeof iat !== "number" ||
				!Number.isSafeInteger(exp) || !Number.isSafeInteger(iat) ||
				!Number.isSafeInteger(policy.maxAssertionAgeSeconds) || policy.maxAssertionAgeSeconds < 1 ||
				!Number.isSafeInteger(policy.credentialGeneration) || policy.credentialGeneration < 1) return unavailable();
			const expiresAt = Math.min(exp, iat + policy.maxAssertionAgeSeconds);
			const now = () => Math.floor(Date.now() / 1000);
			if (iat > now() || expiresAt <= now()) return unavailable();
			const key = await policy.resolveVerificationKey(kid, signal);
			if (!key || key.type !== "public" || (key.algorithm as { hash?: { name: string } }).hash?.name !== "SHA-256" ||
				!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeSegment(signature),
				new TextEncoder().encode(header + "." + payload))) return unavailable();
			const { body, proof } = await readSignedWatchRequest(request, signal);
			const operation = decodeLifecycleClaims(body, policy.lifecycleAudience, now());
			if (operation.installation !== policy.installation ||
				(operation.action !== "preference-read" && operation.action !== "preference-write") ||
				expiresAt <= now() || Date.now() >= submitBeforeMs) return unavailable();
			signal.throwIfAborted();
			// The internal recipient must independently resolve receiver and recheck the credential generation.
			writeForwarded = operation.action === "preference-write";
			const aborted = Promise.withResolvers<never>();
			const onAbort = () => aborted.reject(signal.reason);
			signal.addEventListener("abort", onAbort, { once: true });
			try {
				const response = await Promise.race([aborted.promise, binding.preference({
					installation: policy.installation,
					credentialId: policy.credentialId,
					credentialGeneration: policy.credentialGeneration,
					action: operation.action,
					expiresAt,
					submitBeforeMs,
				}, body, proof)]);
				signal.throwIfAborted();
				if (Date.now() >= submitBeforeMs || Math.min(expiresAt, operation.expiry) <= now()) throw new Error("Watch preference admission expired");
				return response;
			} finally {
				signal.removeEventListener("abort", onAbort);
			}
		} catch {
			return writeForwarded ? Response.json({ error: "watch_preference_outcome_unknown" }, {
				status: 503, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
			}) : unavailable();
		}
	};
}
