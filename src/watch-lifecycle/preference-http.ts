import { readSignedWatchRequest } from "./signed-http";
import { decodeLifecycleClaims, type LifecycleClaims } from "./proof";
import { applyWatchPreference } from "./preference";

const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
const unavailable = () => Response.json({ error: "watch_preference_unavailable" }, { status: 403, headers });

/** No route or restore authority is supplied by this qualification composition. */
export function createWatchPreferenceHttp(
	db: D1Database, audience: string, assertRestoreCurrent: (claims: LifecycleClaims) => void,
) {
	return async (request: Request): Promise<Response> => {
		if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...headers, allow: "POST" } });
		if (request.headers.get("content-type")?.trim().toLowerCase() !== "application/json"
			|| request.headers.has("content-encoding")) return new Response(null, { status: 415, headers });
		let writeMayHaveStarted = false;
		try {
			const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
			const { body, proof } = await readSignedWatchRequest(request, signal);
			const now = Math.floor(Date.now() / 1000);
			const claims = decodeLifecycleClaims(body, audience, now);
			if (claims.action !== "preference-read" && claims.action !== "preference-write") return unavailable();
			const issuer = await db.prepare(`SELECT public_spki_hex FROM watch_lifecycle_issuer
				WHERE installation=? AND epoch=? AND key_fingerprint=? AND scope='watch-lifecycle' AND active=1`)
				.bind(claims.installation, claims.epoch, claims.key_fingerprint).first<{public_spki_hex: string | null}>();
			if (!issuer?.public_spki_hex || !/^[a-f0-9]{182}$/.test(issuer.public_spki_hex)) return unavailable();
			const spki = Uint8Array.from(issuer.public_spki_hex.match(/../g)!, pair => parseInt(pair, 16));
			const check = (verified: LifecycleClaims) => {
				signal.throwIfAborted();
				const result: unknown = assertRestoreCurrent(verified);
				if (result !== undefined) {
					void Promise.resolve(result).catch(() => undefined);
					throw new TypeError("restore authority must be synchronous");
				}
			};
			const receipt = await applyWatchPreference(db, body, proof, spki, audience, now, verified => {
				check(verified);
				writeMayHaveStarted = verified.action === "preference-write";
			});
			if (!receipt) return unavailable();
			check(claims);
			return Response.json(receipt, { headers });
		} catch {
			// Once submitted, a write can commit even if its acknowledgement is lost.
			return writeMayHaveStarted
				? Response.json({ error: "watch_preference_outcome_unknown" }, { status: 503, headers })
				: unavailable();
		}
	};
}
