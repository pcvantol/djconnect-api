import { watchDispatchScopeBinding, watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import { isWatchEnrollmentRegistryEmpty, type EnrollmentChallenge, type EnrollmentIntent } from "./enrollment";
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
				if (!await isWatchEnrollmentRegistryEmpty(owner.db, scope.installation)) return false;
				owner.actor.storage.transactionSync(() => {
					assertExternal();
					// Retry may reuse this exact disabled baseline, but must never reset actor state.
					if (restore.classifyObservation(scope, baseline) !== "confirmed" &&
						!restore.initializeDisabled(scope)) throw new Error("Watch baseline unavailable");
					if (!enrollment.isAdmitted(intent) && !enrollment.insertGrant(intent)) {
						throw new Error("Watch grant unavailable");
					}
				});
				await owner.actor.storage.sync();
				assertCurrent(intent);
				return true;
			} catch {
				return false;
			}
		},
		issue: createWatchEnrollmentIssueHttp(owner.db, async () => ({ intent, publicSpki, assertCurrent })),
		redeem: createWatchEnrollmentRedeemHttp(owner.db, { assertCurrent }),
	};
}

type AdmissionRole = "operator" | "restore";
type AdmissionKeys = Readonly<Record<AdmissionRole, Uint8Array>>;
type AdmissionSignatures = Readonly<Record<AdmissionRole, Uint8Array>>;

export function frameInitialWatchAdmission(role: AdmissionRole, scope: WatchDispatchScope, intent: EnrollmentIntent) {
	const binding = watchDispatchScopeBinding(scope);
	if (binding === null) throw new TypeError("invalid Watch admission scope");
	return new TextEncoder().encode("DJC-WATCH-HA-DEV-INITIAL-ADMISSION-V1\0" + JSON.stringify([
		role, binding, intent.audience, intent.installation, intent.operator_binding,
		intent.restore_fence, intent.key_fingerprint, intent.expected_epoch, intent.expiry,
	]));
}

/** The stable owner supplies pinned keys and still checks current operator and restore state on every use. */
export async function createSignedInitialWatchEnrollment(
	owner: InitialWatchEnrollmentOwner & { readonly trustedAdmissionKeys: AdmissionKeys },
	pairing: WatchDispatchScope, admitted: EnrollmentIntent, spki: Uint8Array, signatures: AdmissionSignatures,
) {
	const scope = Object.freeze({ ...pairing });
	const intent = Object.freeze({ ...admitted });
	const receiverKey = new Uint8Array(spki);
	const operatorKey = new Uint8Array(owner.trustedAdmissionKeys.operator);
	const restoreKey = new Uint8Array(owner.trustedAdmissionKeys.restore);
	const operatorProof = new Uint8Array(signatures.operator);
	const restoreProof = new Uint8Array(signatures.restore);
	const sameKey = (left: Uint8Array, right: Uint8Array) => left.every((byte, index) => byte === right[index]);
	if ([receiverKey, operatorKey, restoreKey].some(key => key.length !== 91) ||
		operatorProof.length !== 64 || restoreProof.length !== 64 ||
		sameKey(operatorKey, restoreKey) || sameKey(receiverKey, operatorKey) || sameKey(receiverKey, restoreKey)) return null;
	const current = () => {
		const remaining = intent.expiry - Math.floor(Date.now() / 1000);
		return Number.isSafeInteger(intent.expiry) && remaining > 0 && remaining <= 30;
	};
	if (!current()) return null;
	async function verify(role: AdmissionRole, keyBytes: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>) {
		const key = await crypto.subtle.importKey("spki", keyBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
		return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature,
			frameInitialWatchAdmission(role, scope, intent));
	}
	try {
		const [operator, restore] = await Promise.all([
			verify("operator", operatorKey, operatorProof),
			verify("restore", restoreKey, restoreProof),
		]);
		if (!operator || !restore || !current()) return null;
	} catch {
		return null;
	}
	return createOwnedInitialWatchEnrollment(owner, scope, intent, receiverKey);
}
