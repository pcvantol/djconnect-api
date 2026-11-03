import { decodeLifecycleClaims, type LifecycleClaims } from "./proof";
import { createWatchRetirement, type WatchRetirementPorts } from "./retirement";
import { readSignedWatchRequest } from "./signed-http";

const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
const unavailable = () => Response.json({ error: "watch_retirement_unavailable" }, { status: 403, headers });

/** Private HTTP composition. The owner must supply the authoritative registry resolver. */
export function createWatchRetirementHttp(
	ports: WatchRetirementPorts,
	resolveScope: (lookup: LifecycleClaims, signal: AbortSignal) => Promise<LifecycleClaims | null>,
) {
	const retire = createWatchRetirement(ports);
	return async (request: Request): Promise<Response> => {
		if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...headers, allow: "POST" } });
		if (request.headers.get("content-type")?.trim().toLowerCase() !== "application/json"
			|| request.headers.has("content-encoding")) return new Response(null, { status: 415, headers });
		const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
		try {
			const { body, proof } = await readSignedWatchRequest(request, signal);
			const lookup = decodeLifecycleClaims(body, ports.audience, ports.now());
			if (lookup.action !== "retire" && lookup.action !== "lifecycle-status") return unavailable();
			// Unverified claims are lookup hints. The resolver returns a separately admitted scope.
			const scope = await resolveScope(lookup, signal);
			if (!scope) return unavailable();
			const outcome = await retire(body, proof, scope, signal);
			if (outcome === "committed") return Response.json({ outcome }, { headers });
			if (outcome === "unknown") {
				return Response.json({ error: "watch_retirement_outcome_unknown" }, { status: 503, headers });
			}
			return unavailable();
		} catch {
			return unavailable();
		}
	};
}
