import { parseStrictJson } from "../surface-push/wire";
import { readSignedWatchRequest } from "./signed-http";
import { issueWatchEnrollmentChallenge, redeemWatchEnrollment } from "./enrollment";

type Intent = Parameters<typeof issueWatchEnrollmentChallenge>[1];
type AssertCurrent = Parameters<typeof issueWatchEnrollmentChallenge>[3];

interface OperatorAdmission {
	intent: Readonly<Intent>;
	publicSpki: Uint8Array;
	assertCurrent: AssertCurrent;
}

const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
const unavailable = () => Response.json({ error: "watch_enrollment_unavailable" }, { status: 403, headers });

/** Closed operator entrypoint. The owner authenticates the request and supplies the exact admitted intent. */
export function createWatchEnrollmentIssueHttp(
	db: D1Database,
	admit?: (request: Request, signal: AbortSignal) => Promise<OperatorAdmission | null>,
) {
	return async (request: Request): Promise<Response> => {
		if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...headers, allow: "POST" } });
		if (!admit) return unavailable();
		const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
		let submitted = false;
		try {
			signal.throwIfAborted();
			const approved = await admit(request, signal);
			if (!approved) return unavailable();
			const { assertCurrent } = approved;
			const challenge = await issueWatchEnrollmentChallenge(db, approved.intent, approved.publicSpki, intent => {
				signal.throwIfAborted();
				const result = assertCurrent(intent);
				submitted = result === undefined;
				return result;
			});
			if (!challenge) return unavailable();
			signal.throwIfAborted();
			return Response.json(challenge, { status: 201, headers });
		} catch {
			return submitted
				? Response.json({ error: "watch_enrollment_outcome_unknown" }, { status: 503, headers })
				: unavailable();
		}
	};
}

/** Closed possession entrypoint. The owner supplies current operator and restore admission. */
export function createWatchEnrollmentRedeemHttp(
	db: D1Database, authority?: Parameters<typeof redeemWatchEnrollment>[4],
) {
	return async (request: Request): Promise<Response> => {
		if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...headers, allow: "POST" } });
		if (!authority) return unavailable();
		if (request.headers.get("content-type")?.trim().toLowerCase() !== "application/json"
			|| request.headers.has("content-encoding")) return new Response(null, { status: 415, headers });
		const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
		let checks = 0;
		let submitted = false;
		try {
			const { body, proof } = await readSignedWatchRequest(request, signal);
			const value = parseStrictJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body)) as Record<string, unknown> | null;
			if (!value || typeof value !== "object" || Object.keys(value).length !== 2 ||
				typeof value.challenge_id !== "string" || typeof value.nonce !== "string") return unavailable();
			const receipt = await redeemWatchEnrollment(db, value.challenge_id, value.nonce, proof, {
				assertCurrent(challenge) {
					signal.throwIfAborted();
					const result = authority.assertCurrent(challenge);
					if (result === undefined && ++checks === 2) submitted = true;
					return result;
				},
			});
			if (!receipt) return unavailable();
			signal.throwIfAborted();
			return Response.json(receipt, { headers });
		} catch {
			return submitted
				? Response.json({ error: "watch_enrollment_outcome_unknown" }, { status: 503, headers })
				: unavailable();
		}
	};
}
