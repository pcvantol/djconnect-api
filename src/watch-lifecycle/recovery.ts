import { verifyLifecycleProof } from "./proof";

interface RecoveryAuthority {
	/** Owning composition checks the operator grant and independent restore admission. */
	assertCurrent(grant: Readonly<{ operator_binding: string; restore_fence: string }>): void;
}

/** Closed qualification source. Caller supplies the current operator-enrolled SPKI. */
export async function recoverWatchReceiver(
	db: D1Database, body: Uint8Array, signature: Uint8Array, expectedSpki: Uint8Array, audience: string,
	now: number, authority: RecoveryAuthority,
): Promise<{ incarnation: string; epoch: number; operation: string } | null> {
	if (body.length > 2048) return null;
	const original = new Uint8Array(body);
	const { assertCurrent } = authority;
	const claims = await verifyLifecycleProof(original, signature, expectedSpki, audience, now);
	if (!claims || claims.action !== "receiver-recover") return null;
	const grant = await db.prepare(`SELECT operator_binding,restore_fence FROM watch_lifecycle_recovery
		WHERE grant_id=? AND consumed=0`).bind(claims.recovery_grant)
		.first<{operator_binding: string; restore_fence: string}>();
	if (!grant) return null;
	const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", original)),
		byte => byte.toString(16).padStart(2, "0")).join("");
	const statement = db.prepare(`UPDATE watch_lifecycle_recovery SET consumed=1,operation=?9,body_hash=?10
		WHERE grant_id=?1 AND installation=?2 AND receiver=?3 AND predecessor_epoch=?4 AND predecessor=?5
		AND epoch=?6 AND key_fingerprint=?7 AND incarnation=?8 AND consumed=0
		AND operator_binding=?11 AND restore_fence=?12 AND expires_at>unixepoch() AND ?13-unixepoch() BETWEEN 1 AND 30
		AND EXISTS (SELECT 1 FROM watch_lifecycle_issuer
			WHERE installation=?2 AND epoch=?6 AND key_fingerprint=?7 AND scope='watch-lifecycle' AND active=1)
		AND EXISTS (SELECT 1 FROM watch_lifecycle_preference
			WHERE installation=?2 AND receiver=?3 AND epoch=?4 AND incarnation=?5)
		AND NOT EXISTS (SELECT 1 FROM watch_lifecycle_incarnation
			WHERE installation=?2 AND receiver=?3 AND incarnation=?8)
		AND (SELECT count(*) FROM watch_lifecycle_incarnation WHERE installation=?2 AND receiver=?3) < 4096
		AND NOT EXISTS (SELECT 1 FROM watch_lifecycle_receipt
			WHERE installation=?2 AND receiver=?3 AND epoch=?6 AND operation=?9)
		RETURNING incarnation,epoch,operation`).bind(
		claims.recovery_grant, claims.installation, claims.receiver, claims.predecessor_epoch, claims.predecessor,
		claims.epoch, claims.key_fingerprint, claims.incarnation, claims.operation, hash,
		grant.operator_binding, grant.restore_fence, claims.expiry,
	);
	const admitted: unknown = assertCurrent(Object.freeze(grant));
	if (admitted !== undefined) {
		void Promise.resolve(admitted).catch(() => undefined);
		throw new TypeError("recovery authority must be synchronous");
	}
	return statement.first();
}
