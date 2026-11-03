import type { WatchDispatchScope } from "./dispatch-identity";
import type { LifecycleClaims } from "./proof";

/** D1 supplies a registry match. The caller still requires independent restore admission. */
export async function resolveWatchRetirementScope(
	db: D1Database, lookup: LifecycleClaims, signal: AbortSignal,
): Promise<WatchDispatchScope | null> {
	if (lookup.action !== "retire" && lookup.action !== "lifecycle-status") return null;
	signal.throwIfAborted();
	const row = await db.prepare(`SELECT pairing.installation, pairing.receiver, pairing.incarnation,
		pairing.epoch, issuer.key_fingerprint
		FROM watch_lifecycle_preference AS pairing
		JOIN watch_lifecycle_issuer AS issuer
			ON issuer.installation=pairing.installation AND issuer.epoch=pairing.epoch
		WHERE pairing.installation=?1 AND pairing.receiver=?2 AND pairing.incarnation=?3
			AND pairing.epoch=?4 AND issuer.key_fingerprint=?5
			AND issuer.scope='watch-lifecycle' AND issuer.active=1
			AND (?6='lifecycle-status' OR pairing.retired=0)`)
		.bind(lookup.installation, lookup.receiver, lookup.incarnation, lookup.epoch,
			lookup.key_fingerprint, lookup.action).first<WatchDispatchScope>();
	signal.throwIfAborted();
	return row;
}
