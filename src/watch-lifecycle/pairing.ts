import { verifyLifecycleProof } from "./proof";

interface PairingReceipt {
	incarnation: string;
	revision: number;
	enabled: number;
	retired: number;
	lifecycle_revision: number;
	lifecycle_operation: string;
}

type LifecycleStatus =
	| { state: "unknown" | "superseded" }
	| { state: "committed_current"; incarnation: string; revision: number; operation: string; body_hash: string; retired: number };

const currentIssuer = `
	?5-unixepoch() BETWEEN 1 AND 30 AND EXISTS (
		SELECT 1 FROM watch_lifecycle_issuer
		WHERE installation=?1 AND epoch=?3 AND key_fingerprint=?6
		AND scope='watch-lifecycle' AND active=1
	)
`;
const result = "incarnation, revision, enabled, retired, lifecycle_revision, lifecycle_operation";
const scope = "installation=?1 AND receiver=?2 AND epoch=?3";
const availableOperation = `NOT EXISTS (SELECT 1 FROM watch_lifecycle_receipt WHERE ${scope} AND operation=?7)`;
const availablePairing = `(SELECT count(*) FROM watch_lifecycle_incarnation WHERE installation=?1 AND receiver=?2) < 4096`;

/** Qualification composition. Issuer enrollment and restore admission are external prerequisites. */
export async function applyWatchPairing(
	db: D1Database, body: Uint8Array, signature: Uint8Array, expectedSpki: Uint8Array, audience: string, now: number,
): Promise<PairingReceipt | LifecycleStatus | null> {
	if (body.length > 2048) return null;
	const original = new Uint8Array(body);
	const claims = await verifyLifecycleProof(original, signature, expectedSpki, audience, now);
	if (!claims) return null;
	const binding = [claims.installation, claims.receiver, claims.epoch, claims.incarnation, claims.expiry, claims.key_fingerprint];
	if (claims.action === "lifecycle-status") {
		const row = await db.prepare(`SELECT
			CASE WHEN old.operation IS NULL THEN 'unknown'
				WHEN old.body_hash<>?8 OR old.incarnation<>?4 THEN 'denied'
				WHEN current.lifecycle_revision=old.revision AND current.incarnation=old.incarnation
					THEN 'committed_current' ELSE 'superseded' END AS state,
			old.incarnation,old.revision,old.operation,old.body_hash,old.retired
			FROM (SELECT 1)
			LEFT JOIN watch_lifecycle_receipt AS old
				ON old.installation=?1 AND old.receiver=?2 AND old.epoch=?3 AND old.operation=?7
			LEFT JOIN watch_lifecycle_preference AS current
				ON current.installation=?1 AND current.receiver=?2 AND current.epoch=?3
			WHERE ${currentIssuer}`)
			.bind(...binding, claims.target_operation, claims.target_body_sha256)
			.first<LifecycleStatus | { state: "denied" }>();
		if (!row || row.state === "denied") return null;
		return row.state === "committed_current" ? row : { state: row.state };
	}

	const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", original)),
		byte => byte.toString(16).padStart(2, "0")).join("");
	const parameters = [...binding, claims.operation, hash];
	const unused = `NOT EXISTS (SELECT 1 FROM watch_lifecycle_incarnation
		WHERE installation=?1 AND receiver=?2 AND incarnation=?4)`;
	switch (claims.action) {
		case "pair":
			return db.prepare(`INSERT INTO watch_lifecycle_preference(
					installation,receiver,epoch,incarnation,lifecycle_revision,lifecycle_operation,lifecycle_hash)
				SELECT ?1,?2,?3,?4,1,?7,?8 WHERE ${currentIssuer} AND ${unused}
					AND ${availableOperation} AND ${availablePairing}
				ON CONFLICT(installation,receiver) DO NOTHING RETURNING ${result}`)
				.bind(...parameters).first<PairingReceipt>();
		case "replace":
			return db.prepare(`UPDATE watch_lifecycle_preference
				SET incarnation=?4, revision=0, enabled=0, sealed=0, retired=0, operation=NULL, body_hash=NULL,
					lifecycle_revision=lifecycle_revision+1, lifecycle_operation=?7, lifecycle_hash=?8
				WHERE ${scope} AND incarnation=?9 AND retired=0
					AND ${currentIssuer} AND ${unused} AND ${availableOperation} AND ${availablePairing}
				RETURNING ${result}`).bind(...parameters, claims.predecessor).first<PairingReceipt>();
		case "retire":
			return db.prepare(`UPDATE watch_lifecycle_preference SET enabled=0, sealed=1, retired=1,
					lifecycle_revision=lifecycle_revision+1, lifecycle_operation=?7, lifecycle_hash=?8
				WHERE ${scope} AND incarnation=?4 AND retired=0 AND ${currentIssuer} AND ${availableOperation}
				RETURNING ${result}`).bind(...parameters).first<PairingReceipt>();
		default:
			return null;
	}
}
