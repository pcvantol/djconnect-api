import { base64Url } from "../crypto";
import { parseStrictJson } from "../surface-push/wire";
import { createWatchAccessKeyResolver } from "../watch-lifecycle/access-jwks";

const identifier = /^[A-Za-z0-9_-]{1,128}$/;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export const widgetCoreAccessClientId = /^[A-Za-z0-9_-]{1,128}\.access$/;

function decodeSegment(value: string): Uint8Array<ArrayBuffer> {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("invalid Access segment");
	const decoded = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0));
	if (base64Url(decoded.buffer) !== value) throw new TypeError("noncanonical Access segment");
	return decoded;
}

function claims(value: string): Record<string, unknown> {
	const parsed = parseStrictJson(decoder.decode(decodeSegment(value)));
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("invalid Access claims");
	return parsed as Record<string, unknown>;
}

export async function verifyWidgetCoreAccess(
	request: Request, ctx: ExecutionContext, issuer: string, audience: string, clientId: string,
	expiresAt: number, configurationCurrent: () => boolean, resolveKeys = createWatchAccessKeyResolver,
) {
	if (!ctx.access || request.headers.has("cookie") || request.headers.has("origin") ||
		request.headers.has("content-encoding")) return null;
	const token = request.headers.get("cf-access-jwt-assertion");
	if (!token || token.length > 8192) return null;
	const parts = token.split(".");
	if (parts.length !== 3) return null;
	const [header, payload, signature] = parts;
	const { alg, kid, crit } = claims(header);
	const { iss, aud, common_name, type, sub, exp, iat } = claims(payload);
	// Access service tokens can encode one audience as a string or a singleton array.
	const audienceMatches = aud === audience || (Array.isArray(aud) && aud.length === 1 && aud[0] === audience);
	if (alg !== "RS256" || crit !== undefined || typeof kid !== "string" || !identifier.test(kid) ||
		iss !== issuer || !audienceMatches ||
		common_name !== clientId || type !== "app" || sub !== "" ||
		typeof exp !== "number" || typeof iat !== "number" || !Number.isSafeInteger(exp) ||
		!Number.isSafeInteger(iat)) return null;
	const requestExpiry = Math.min(expiresAt, exp * 1000, (iat + 30) * 1000);
	const current = () => !request.signal.aborted && iat <= Math.floor(Date.now() / 1000) &&
		Date.now() < requestExpiry && configurationCurrent();
	if (!current()) return null;
	const key = await resolveKeys(issuer)(kid, AbortSignal.any([request.signal, AbortSignal.timeout(3000)]));
	if (!key || key.type !== "public" ||
		(key.algorithm as { hash?: { name: string } }).hash?.name !== "SHA-256" ||
		!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeSegment(signature),
			Uint8Array.from(new TextEncoder().encode(header + "." + payload))) || !current()) return null;
	return { current, expiresAt: requestExpiry };
}
