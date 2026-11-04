import { watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import type { EnrollmentChallenge, EnrollmentIntent } from "./enrollment";
import { WatchEnrollmentAuthority } from "./enrollment-authority";
import { createWatchEnrollmentIssueHttp, createWatchEnrollmentRedeemHttp } from "./enrollment-http";
import { WatchRestoreAuthority } from "./restore-authority";

interface InitialWatchEnrollmentOwner {
	db: D1Database;
	actor: DurableObjectState;
	namespace: Pick<DurableObjectNamespace, "idFromName">;
	/** Both checks use independently provisioned authority in this actor. */
	assertOperatorCurrent(scope: WatchDispatchScope, intent: EnrollmentIntent): void;
	assertRestoreWitnessCurrent(scope: WatchDispatchScope, intent: EnrollmentIntent): void;
}

const baseline = Object.freeze({ revision: 0, operation: null, body_hash: null, enabled: 0, sealed: 0 });
const digest = /^[a-f0-9]{64}$/;

function requireSynchronous(result: unknown): void {
	if (result === undefined) return;
	void Promise.resolve(result).catch(() => undefined);
	throw new TypeError("Watch enrollment authority must be synchronous");
}

/** The owning actor supplies the verified pairing and current operator/restore witnesses. First issuer only. */
export async function createOwnedInitialWatchEnrollment(
	owner: InitialWatchEnrollmentOwner | undefined, pairing: WatchDispatchScope,
	admitted: EnrollmentIntent, spki: Uint8Array,
) {
	if (!owner || typeof owner.assertOperatorCurrent !== "function" ||
		typeof owner.assertRestoreWitnessCurrent !== "function") return null;
	const scope = Object.freeze({ ...pairing });
	const intent = Object.freeze({ ...admitted });
	const publicSpki = new Uint8Array(spki);
	const name = await watchRestoreActorName(scope);
	if (!name || !owner.actor.id.equals(owner.namespace.idFromName(name)) ||
		intent.expected_epoch !== 0 || scope.epoch !== 1 || scope.installation !== intent.installation ||
		scope.key_fingerprint !== intent.key_fingerprint || !digest.test(intent.operator_binding) ||
		!digest.test(intent.restore_fence) || !/^[\x21-\x7e]{1,160}$/.test(intent.audience) ||
		publicSpki.length !== 91) return null;
	try {
		const fingerprint = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", publicSpki)),
			byte => byte.toString(16).padStart(2, "0")).join("");
		if (fingerprint !== intent.key_fingerprint) return null;
		await crypto.subtle.importKey("spki", publicSpki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	} catch {
		return null;
	}

	const enrollment = new WatchEnrollmentAuthority(owner.actor.storage, intent.installation);
	const restore = new WatchRestoreAuthority(owner.actor.storage);
	const assertExternal = () => {
		const remaining = intent.expiry - Math.floor(Date.now() / 1000);
		if (!Number.isSafeInteger(intent.expiry) || remaining < 1 || remaining > 30) throw new Error("Watch grant expired");
		requireSynchronous(owner.assertOperatorCurrent(scope, intent));
		requireSynchronous(owner.assertRestoreWitnessCurrent(scope, intent));
	};
	const assertCurrent = (value: EnrollmentIntent | Readonly<EnrollmentChallenge>) => {
		assertExternal();
		if (value.operator_binding !== intent.operator_binding || value.restore_fence !== intent.restore_fence ||
			restore.classifyObservation(scope, baseline) !== "confirmed") throw new Error("Watch restore not admitted");
		enrollment.assertCurrent(value);
	};

	return {
		async prepare() {
			try {
				assertExternal();
				// A pre-existing actor cannot be reset to disabled by this initial-only entrypoint.
				if (!restore.initializeDisabled(scope)) return false;
				await owner.actor.storage.sync();
				assertExternal();
				return await enrollment.authorize(intent);
			} catch {
				return false;
			}
		},
		issue: createWatchEnrollmentIssueHttp(owner.db, async () => ({ intent, publicSpki, assertCurrent })),
		redeem: createWatchEnrollmentRedeemHttp(owner.db, { assertCurrent }),
	};
}
