import { decodeLifecycleClaims, type LifecycleClaims } from "./proof";
import { applyWatchPreference } from "./preference";

const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
const unavailable = () => Response.json({ error: "watch_preference_unavailable" }, { status: 403, headers });

async function readBody(request: Request, signal: AbortSignal) {
	const reader = request.body?.getReader();
	if (!reader) throw new TypeError("missing body");
	const cancel = () => { void reader.cancel().catch(() => undefined); };
	signal.addEventListener("abort", cancel, { once: true });
	const buffer = new Uint8Array(2048);
	let size = 0;
	try {
		for (;;) {
			signal.throwIfAborted();
			const chunk = await reader.read();
			signal.throwIfAborted();
			if (chunk.done) return buffer.slice(0, size);
			if (size + chunk.value.length > buffer.length) throw new TypeError("oversized body");
			buffer.set(chunk.value, size);
			size += chunk.value.length;
		}
	} finally {
		signal.removeEventListener("abort", cancel);
		cancel();
	}
}

/** No route or restore authority is supplied by this qualification composition. */
export function createWatchPreferenceHttp(
	db: D1Database, audience: string, assertRestoreCurrent: (claims: LifecycleClaims) => void,
) {
	return async (request: Request): Promise<Response> => {
		if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...headers, allow: "POST" } });
		if (request.headers.get("content-type")?.trim().toLowerCase() !== "application/json"
			|| request.headers.has("content-encoding")) return new Response(null, { status: 415, headers });
		try {
			const signature = request.headers.get("djc-watch-lifecycle-signature") ?? "";
			if (!/^[A-Za-z0-9_-]{85}[AQgw]$/.test(signature)) return unavailable();
			const proof = Uint8Array.from(atob(signature.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
			const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
			const body = await readBody(request, signal);
			const now = Math.floor(Date.now() / 1000);
			const claims = decodeLifecycleClaims(body, audience, now);
			if (claims.action !== "preference-read" && claims.action !== "preference-write") return unavailable();
			const issuer = await db.prepare(`SELECT public_spki_hex FROM watch_lifecycle_issuer
				WHERE installation=? AND epoch=? AND key_fingerprint=? AND scope='watch-lifecycle' AND active=1`)
				.bind(claims.installation, claims.epoch, claims.key_fingerprint).first<{public_spki_hex: string | null}>();
			if (!issuer?.public_spki_hex || !/^[a-f0-9]{182}$/.test(issuer.public_spki_hex)) return unavailable();
			const spki = Uint8Array.from(issuer.public_spki_hex.match(/../g)!, pair => parseInt(pair, 16));
			const receipt = await applyWatchPreference(db, body, proof, spki, audience, now, verified => {
				signal.throwIfAborted();
				return assertRestoreCurrent(verified);
			});
			signal.throwIfAborted();
			return receipt ? Response.json(receipt, { headers }) : unavailable();
		} catch {
			return unavailable();
		}
	};
}
