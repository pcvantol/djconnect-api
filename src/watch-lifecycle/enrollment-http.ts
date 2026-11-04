import { issueWatchEnrollmentChallenge } from "./enrollment";

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
