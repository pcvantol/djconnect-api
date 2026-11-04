import { parseStrictJson } from "../surface-push/wire";

const teamIssuer = /^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/;
const keyId = /^[A-Za-z0-9_-]{1,128}$/;
const base64url = /^[A-Za-z0-9_-]+$/;
const maxBytes = 64 * 1024;

export function createWatchAccessKeyResolver(issuer: string, fetcher: typeof fetch = fetch) {
	const endpoint = teamIssuer.test(issuer) ? issuer + "/cdn-cgi/access/certs" : null;
	return async (kid: string, signal: AbortSignal): Promise<CryptoKey | null> => {
		if (!endpoint || !keyId.test(kid)) return null;
		signal.throwIfAborted();
		const response = await fetcher(endpoint, {
			redirect: "error", cache: "no-store", headers: { accept: "application/json" }, signal,
		});
		if (response.status !== 200 || response.redirected || (response.url && response.url !== endpoint)) {
			void response.body?.cancel().catch(() => undefined);
			return null;
		}
		const reader = response.body?.getReader();
		if (!reader) return null;
		const buffer = new Uint8Array(maxBytes);
		let length = 0;
		try {
			for (;;) {
				signal.throwIfAborted();
				const { done, value } = await reader.read();
				signal.throwIfAborted();
				if (done) break;
				if (value.length > buffer.length - length) return null;
				buffer.set(value, length);
				length += value.length;
			}
		} finally {
			void reader.cancel().catch(() => undefined);
		}
		const body = parseStrictJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
			.decode(buffer.subarray(0, length))) as { keys?: unknown } | null;
		if (!Array.isArray(body?.keys) || body.keys.length > 32) return null;
		const matches = body.keys.filter(key => key && typeof key === "object" && key.kid === kid);
		if (matches.length !== 1) return null;
		const { kty, alg, use, n, e } = matches[0];
		if (kty !== "RSA" || alg !== "RS256" || use !== "sig" || typeof n !== "string" ||
			n.length < 342 || n.length > 683 || !base64url.test(n) ||
			typeof e !== "string" || e.length > 8 || !base64url.test(e)) return null;
		const key = await crypto.subtle.importKey("jwk", { kty, alg, n, e },
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
		signal.throwIfAborted();
		return (key.algorithm as { modulusLength: number }).modulusLength >= 2048 ? key : null;
	};
}
