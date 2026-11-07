import { base64Encode, sha256Hex } from "../crypto";
import { verifyCorePairingDeclaration } from "./core-pairing";
import { watchDispatchScopeBinding, watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import { createSignedInitialWatchEnrollment } from "./owned-enrollment";

type EnrollmentOwner = Parameters<typeof createSignedInitialWatchEnrollment>[0];
type PendingPairing = Parameters<typeof verifyCorePairingDeclaration>[2];
type Intent = Parameters<typeof createSignedInitialWatchEnrollment>[2];
type Proofs = Parameters<typeof createSignedInitialWatchEnrollment>[4];
type Verified = NonNullable<Awaited<ReturnType<typeof verifyCorePairingDeclaration>>>;

interface PairingOwner extends EnrollmentOwner {
	assertCorePairingCurrent(declaration: Verified["declaration"]): void;
}

const digest = /^[a-f0-9]{64}$/;

export function bindWatchPairingEvidence(
	role: "operator" | "restore", declarationHash: string, evidenceHash: string,
): Promise<string> {
	if (!digest.test(declarationHash) || !digest.test(evidenceHash)) throw new TypeError("Invalid Watch pairing evidence");
	return sha256Hex("DJC-WATCH-HA-DEV-PAIRING-EVIDENCE-V1\0" + JSON.stringify([role, declarationHash, evidenceHash]));
}

/** Only the private owner supplies the pending request, assigned scope and independent evidence. */
export async function createOwnedWatchPairing(
	owner: PairingOwner, assigned: WatchDispatchScope, request: PendingPairing,
	now = () => Math.floor(Date.now() / 1000),
) {
	const scope = Object.freeze({ ...assigned });
	const pending = Object.freeze({ ...request, coreSpki: new Uint8Array(request.coreSpki) });
	const name = await watchRestoreActorName(scope);
	if (!name || !owner.actor.id.equals(owner.namespace.idFromName(name)) ||
		scope.epoch !== 1 || scope.installation !== pending.installation || pending.coreSpki.length !== 91) return null;
	const pinnedKey = base64Encode(pending.coreSpki);
	const requestBinding = JSON.stringify([pending.registryId, pending.declarationId, pending.installation,
		pending.deviceId, pending.expiresAt, pinnedKey, watchDispatchScopeBinding(scope)]);
	const { storage } = owner.actor;
	const sql = storage.sql;
	sql.exec(`CREATE TABLE IF NOT EXISTS watch_core_pairing_request (
		id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL, declaration_hash TEXT
	)`);
	const row = () => sql.exec<{ binding: string; declaration_hash: string | null }>(
		"SELECT binding,declaration_hash FROM watch_core_pairing_request WHERE id=1").toArray()[0];
	const current = (expiry: number, issuedAt = 0) => {
		const at = now();
		return Number.isSafeInteger(at) && Number.isSafeInteger(expiry) &&
			at >= issuedAt && at < expiry && expiry - at <= 30;
	};
	const assertCurrent = (verified: Verified) => {
		const saved = row();
		if (!saved || saved.binding !== requestBinding || saved.declaration_hash !== verified.declarationHash ||
			!current(verified.declaration.expires_at, verified.declaration.issued_at)) {
			throw new Error("Watch pairing unavailable");
		}
		const result: unknown = owner.assertCorePairingCurrent(verified.declaration);
		if (result !== undefined) {
			void Promise.resolve(result).catch(() => undefined);
			throw new TypeError("Core pairing authority must be synchronous");
		}
	};
	const verify = async (body: Uint8Array, signature: string) => {
		if (row()?.binding !== requestBinding) return null;
		const verified = await verifyCorePairingDeclaration(body, signature, pending, now);
		return verified?.declaration.key_fingerprint === scope.key_fingerprint ? verified : null;
	};
	return {
		async beginPairingDeclaration() {
			if (!current(pending.expiresAt)) return false;
			sql.exec("INSERT OR IGNORE INTO watch_core_pairing_request VALUES (1,?,NULL)", requestBinding);
			await storage.sync();
			return current(pending.expiresAt) && row()?.binding === requestBinding;
		},
		async admitDeclaration(body: Uint8Array, signature: string) {
			try {
				const verified = await verify(body, signature);
				if (!verified || !current(verified.declaration.expires_at)) return null;
				// The compare-and-set and current pairing check share one SQLite transaction.
				storage.transactionSync(() => {
					sql.exec(`UPDATE watch_core_pairing_request SET declaration_hash=?
						WHERE id=1 AND binding=? AND declaration_hash IS NULL`, verified.declarationHash, requestBinding);
					assertCurrent(verified);
				});
				await storage.sync();
				assertCurrent(verified);
				return Object.freeze({ scope, declarationHash: verified.declarationHash, expiresAt: verified.declaration.expires_at });
			} catch {
				return null;
			}
		},
		async initialEnrollment(body: Uint8Array, signature: string, input: Intent, proofs: Proofs,
			evidence: Readonly<{ operator: string; restore: string }>) {
			const intent = Object.freeze({ ...input });
			const signatures = { operator: new Uint8Array(proofs.operator), restore: new Uint8Array(proofs.restore) };
			const { operator, restore } = evidence;
			try {
				const verified = await verify(body, signature);
				if (!verified || operator === restore || intent.expiry > verified.declaration.expires_at) return null;
				const [operatorBinding, restoreFence] = await Promise.all([
					bindWatchPairingEvidence("operator", verified.declarationHash, operator),
					bindWatchPairingEvidence("restore", verified.declarationHash, restore),
				]);
				if (intent.operator_binding !== operatorBinding || intent.restore_fence !== restoreFence) return null;
				assertCurrent(verified);
				const enrollment = await createSignedInitialWatchEnrollment({
					...owner,
					assertOperatorCurrent(scope, intent) {
						assertCurrent(verified);
						return owner.assertOperatorCurrent(scope, intent);
					},
				}, scope, intent, pending.coreSpki, signatures);
				assertCurrent(verified);
				return enrollment;
			} catch {
				return null;
			}
		},
	};
}
