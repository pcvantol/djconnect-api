import { verifyLifecycleProof } from "./proof";

interface PairingReceipt {
	incarnation: string;
	revision: number;
	enabled: number;
	retired: number;
}

const currentIssuer = `
	?5-unixepoch() BETWEEN 1 AND 30 AND EXISTS (
		SELECT 1 FROM watch_lifecycle_issuer
		WHERE installation=?1 AND epoch=?3 AND key_fingerprint=?6
		AND scope='watch-lifecycle' AND active=1
	)
`;
const result = "incarnation, revision, enabled, retired";

/** Qualification composition. Issuer enrollment and restore admission are external prerequisites. */
export async function applyWatchPairing(
	db: D1Database, body: Uint8Array, signature: Uint8Array, expectedSpki: Uint8Array, audience: string, now: number,
): Promise<PairingReceipt | null> {
	const claims = await verifyLifecycleProof(body, signature, expectedSpki, audience, now);
	if (!claims) return null;
	const binding = [claims.installation, claims.receiver, claims.epoch, claims.incarnation, claims.expiry, claims.key_fingerprint];
	const unused = `NOT EXISTS (SELECT 1 FROM watch_lifecycle_incarnation
		WHERE installation=?1 AND receiver=?2 AND incarnation=?4)`;
	switch (claims.action) {
		case "pair":
			return db.prepare(`INSERT INTO watch_lifecycle_preference(installation,receiver,epoch,incarnation)
				SELECT ?1,?2,?3,?4 WHERE ${currentIssuer} AND ${unused}
				ON CONFLICT(installation,receiver) DO NOTHING RETURNING ${result}`)
				.bind(...binding).first<PairingReceipt>();
		case "replace":
			return db.prepare(`UPDATE watch_lifecycle_preference
				SET incarnation=?4, revision=0, enabled=0, sealed=0, retired=0, operation=NULL, body_hash=NULL
				WHERE installation=?1 AND receiver=?2 AND epoch=?3 AND incarnation=?7 AND retired=0
					AND ${currentIssuer} AND ${unused} RETURNING ${result}`)
				.bind(...binding, claims.predecessor).first<PairingReceipt>();
		case "retire":
			return db.prepare(`UPDATE watch_lifecycle_preference SET enabled=0, sealed=1, retired=1
				WHERE installation=?1 AND receiver=?2 AND epoch=?3 AND incarnation=?4
					AND ${currentIssuer} RETURNING ${result}`)
				.bind(...binding).first<PairingReceipt>();
		default:
			return null;
	}
}
