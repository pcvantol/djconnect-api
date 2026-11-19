import { base64Url } from "../crypto";
import { createWatchAccessKeyResolver } from "../watch-lifecycle/access-jwks";
import { createSurfaceService, type SurfaceServiceOptions } from "./composition";
import { parseStrictJson } from "./wire";

// Pin the bindings consumed by Surface Push for this ingress generation.
const surfaceEnvironmentFields = [
	"DB", "DJCONNECT_RELAY_SECRET", "APNS_TOKEN_ENCRYPTION_KEY", "APNS_TEAM_ID", "APNS_KEY_ID",
	"APNS_PRIVATE_KEY", "APNS_ENVIRONMENT", "APNS_TOPIC_IOS", "APNS_TOPIC_MACOS", "APNS_TOPIC_WATCHOS",
] as const;

const prefix = "/v1/push/surface/";
const relayPaths = new Set(["register", "revoke", "event", "status"].map(action => prefix + action));
const issuerPaths = new Set(["challenge", "issue", "status", "withdraw"].map(action => prefix + "issuer/" + action));
const redemptionPath = prefix + "enrollment/redeem";
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

interface WidgetAccessConfiguration extends SurfaceServiceOptions {
	origin: string;
	issuer: string;
	audience: string;
	clientId: string;
	credentialGeneration: number;
	maxAssertionAgeSeconds: number;
	isCredentialCurrent(generation: number): boolean;
	resolveVerificationKey?: ReturnType<typeof createWatchAccessKeyResolver>;
}

function segment(value: string): Uint8Array<ArrayBuffer> {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("Invalid Access assertion");
	const bytes = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), c => c.charCodeAt(0));
	if (base64Url(bytes.buffer) !== value) throw new TypeError("Invalid Access assertion");
	return bytes;
}

function claims(value: string): Record<string, unknown> {
	const parsed = parseStrictJson(decoder.decode(segment(value)));
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("Invalid Access claims");
	return parsed as Record<string, unknown>;
}

function denied(status: 403 | 404 | 503) {
	const error = status === 404 ? "surface_route_not_found" :
		status === 503 ? "surface_service_unavailable" : "surface_access_required";
	return Response.json({ contract_version: 1, success: false, error }, {
		status, headers: { "cache-control": "no-store", "referrer-policy": "no-referrer", "x-content-type-options": "nosniff" },
	});
}

/** Source-only HA-dev ingress. Deploy only on the dedicated hostname and WidgetKit database. */
export function createPrivateWidgetIngress(options: WidgetAccessConfiguration) {
	const policy = Object.freeze({ ...options });
	const resolveKey = policy.resolveVerificationKey ?? createWatchAccessKeyResolver(policy.issuer);
	const now = policy.now ?? Date.now;
	const environment = surfaceEnvironmentFields.map(name => policy.env[name]);
	const optionNames = Object.keys(policy) as (keyof WidgetAccessConfiguration)[];
	let retired = false;
	const matches = () => {
		if (!retired) {
			try {
				retired = !optionNames.every(key => options[key] === policy[key]) ||
					!surfaceEnvironmentFields.every((name, index) => policy.env[name] === environment[index]);
			} catch {
				retired = true;
			}
		}
		return !retired;
	};
	const origin = new URL(policy.origin);
	if (origin.protocol !== "https:" || origin.origin !== policy.origin || origin.port ||
		policy.origin === "https://api.djconnect.dev" || !policy.audience ||
		!policy.clientId || !Number.isSafeInteger(policy.credentialGeneration) || policy.credentialGeneration < 1 ||
		!Number.isSafeInteger(policy.maxAssertionAgeSeconds) || policy.maxAssertionAgeSeconds < 1 ||
		policy.maxAssertionAgeSeconds > 30) throw new TypeError("Invalid private WidgetKit ingress configuration");

	return async (request: Request, ctx: Pick<ExecutionContext, "access">): Promise<Response> => {
		const path = new URL(request.url).pathname;
		const issuer = issuerPaths.has(path), relay = relayPaths.has(path), redeem = path === redemptionPath;
		if ((!issuer && !relay && !redeem) || request.url !== policy.origin + path || request.method !== "POST") return denied(404);
		if (!ctx.access || request.headers.has("origin") || request.headers.has("cookie") ||
			request.headers.has("content-encoding") ||
			request.headers.get("content-type")?.trim().toLowerCase() !== "application/json") return denied(403);
		const token = request.headers.get("cf-access-jwt-assertion");
		if (!token || token.length > 8192) return denied(403);
		const signal = AbortSignal.any([request.signal, AbortSignal.timeout(10_000)]);
		let admitted = false;
		try {
			const parts = token.split(".");
			if (parts.length !== 3) return denied(403);
			const [header, payload, signature] = parts;
			const { alg, kid, crit } = claims(header);
			const { iss, aud, common_name, type, sub, exp, iat } = claims(payload);
			if (alg !== "RS256" || typeof kid !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(kid) ||
				crit !== undefined || iss !== policy.issuer || !Array.isArray(aud) || aud.length !== 1 ||
				aud[0] !== policy.audience || common_name !== policy.clientId || type !== "app" || sub !== "" ||
				typeof exp !== "number" || !Number.isSafeInteger(exp) ||
				typeof iat !== "number" || !Number.isSafeInteger(iat)) return denied(403);
			const expiresAt = Math.min(exp, iat + policy.maxAssertionAgeSeconds);
			let highWater = 0;
			const isCurrent = () => {
				const wall = now();
				if (!Number.isSafeInteger(wall) || wall < highWater) return false;
				highWater = wall;
				const clock = Math.floor(wall / 1000);
				return !signal.aborted && iat <= clock && clock < expiresAt &&
					matches() && policy.isCredentialCurrent(policy.credentialGeneration) === true &&
					(policy.isCurrent?.() ?? true) === true;
			};
			if (!isCurrent()) return denied(403);
			const key = await resolveKey(kid, signal);
			if (!key || key.type !== "public" ||
				(key.algorithm as { hash?: { name: string } }).hash?.name !== "SHA-256" || !isCurrent() ||
				!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, segment(signature), encoder.encode(header + "." + payload)) ||
				!isCurrent()) return denied(403);

			const authorization = request.headers.get("authorization");
			if (issuer ? authorization !== null :
				!authorization || !(redeem ? /^Bearer djce_[A-Za-z0-9_-]{43}$/ : /^Bearer djcs_[A-Za-z0-9_-]{43}$/).test(authorization)) {
				return denied(403);
			}
			// Allowlist downstream headers so Access credentials never cross the handler boundary.
			const headers = new Headers({ "content-type": "application/json" });
			if (authorization) headers.set("authorization", authorization);
			// The closed enrollment handler expects its canonical request origin. This is
			// an in-process Request only; the original signed path and body stay intact.
			const downstream = new Request("https://api.djconnect.dev" + path, {
				method: "POST", body: request.body, headers, signal,
			});
			admitted = true;
			// Request-local service state keeps this assertion's deadline out of concurrent requests.
			const service = createSurfaceService({ env: policy.env, now, fetcher: policy.fetcher, isCurrent });
			try {
				const response = await service.handle(downstream);
				return isCurrent() ? response : denied(503);
			} finally {
				service.close();
			}
		} catch {
			return denied(admitted ? 503 : 403);
		}
	};
}
