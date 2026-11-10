import { createProductRendezvousHandler, directEdgeIp, type ProductRendezvousEnv } from "./composition";
import { unavailableRendezvousResponse } from "./perimeter";
import { TESTFLIGHT_POLICY, testflightRelease } from "../../qualification/rendezvous/testflight-release.mjs";

// The loopback qualifier replaces this exact literal. Production uses only the
// separately configured, finite TestFlight trial below.
const PRODUCT_RENDEZVOUS_ENABLED = false as boolean;
const QR_LIFETIME_MS = 120_000;
const MAX_TRIAL_MS = 2 * 60 * 60 * 1000;

type TrialEnv = ProductRendezvousEnv & { RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT?: string };

function trialEnd(env: TrialEnv | undefined, now: number): number | undefined {
	if (env?.ASSERTION_POLICY_ENABLED !== TESTFLIGHT_POLICY ||
		env.RENDEZVOUS_CAPACITY_POLICY !== "private-household/1") return;
	const release = testflightRelease(env);
	if (!release || release.min !== release.max) return;

	const startsAt = Number(env.RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT);
	const endsAt = Number(env.ASSERTION_POLICY_EXPIRES_AT);
	if (!Number.isSafeInteger(startsAt) || startsAt <= 0 ||
		String(startsAt) !== env.RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT ||
		!Number.isSafeInteger(endsAt) || String(endsAt) !== env.ASSERTION_POLICY_EXPIRES_AT ||
		endsAt - startsAt <= QR_LIFETIME_MS || endsAt - startsAt > MAX_TRIAL_MS ||
		now < startsAt || now >= endsAt) return;
	return endsAt;
}

/** Reserve rendezvous before the existing API touches credentials or storage. */
export async function dispatchRendezvousRequest(request: Request, env: unknown): Promise<Response | undefined> {
	const unavailable = unavailableRendezvousResponse(request);
	if (!unavailable) return;
	const bindings = env as TrialEnv | undefined;
	if (PRODUCT_RENDEZVOUS_ENABLED) return createProductRendezvousHandler(bindings!)(request);

	try {
		if (!bindings || !Object.hasOwn(bindings, "RENDEZVOUS_PUBLIC_TRIAL_STARTS_AT")) return unavailable;
		const startedAt = Date.now();
		const endsAt = trialEnd(bindings, startedAt);
		if (endsAt === undefined) return unavailable;
		const create = new URL(request.url).pathname === "/v1/rendezvous/create";
		if (create && startedAt >= endsAt - QR_LIFETIME_MS) return unavailable;
		// Check even OPTIONS before handing the request to the route handler.
		directEdgeIp(request);
		const response = await createProductRendezvousHandler(bindings!)(request);
		if (create && response.status === 201) {
			const { created_at, expires_at } = await response.clone().json<{ created_at: number; expires_at: number }>();
			if (!Number.isSafeInteger(created_at) || !Number.isSafeInteger(expires_at) ||
				created_at < startedAt || expires_at - created_at !== QR_LIFETIME_MS ||
				expires_at >= endsAt || expires_at <= Date.now()) return unavailable;
		}
		const now = Date.now();
		return now >= startedAt && now < endsAt ? response : unavailable;
	} catch {
		return unavailable;
	}
}
