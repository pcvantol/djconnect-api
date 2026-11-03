import { verifyLifecycleProof, type LifecycleClaims } from "./proof";

export interface PreferenceReceipt {
	incarnation: string;
	revision: number;
	operation: string | null;
	enabled: number;
	sealed: number;
}

const current = `
	installation=?1 AND receiver=?2 AND epoch=?3 AND incarnation=?4 AND retired=0
	AND ?5-unixepoch() BETWEEN 1 AND 30
	AND EXISTS (SELECT 1 FROM watch_lifecycle_issuer AS issuer
		WHERE issuer.installation=?1 AND issuer.epoch=?3 AND issuer.key_fingerprint=?6
		AND issuer.scope='watch-lifecycle' AND issuer.active=1)
`;
const receipt = "incarnation, revision, operation, enabled, sealed";
const intentScope = "installation=?1 AND receiver=?2 AND epoch=?3 AND incarnation=?4";
const capacity = 4096;

/** Closed composition candidate. Expected SPKI must come from trusted operator enrollment. */
export async function applyWatchPreference(
	db: D1Database, body: Uint8Array, signature: Uint8Array, expectedSpki: Uint8Array, audience: string, now: number, assertCurrent: (claims: LifecycleClaims) => void,
): Promise<PreferenceReceipt | null> {
	if (body.length > 2048) return null;
	const original = new Uint8Array(body);
	const claims = await verifyLifecycleProof(original, signature, expectedSpki, audience, now);
	if (!claims) return null;
	const check = () => {
		const result: unknown = assertCurrent(claims);
		if (result !== undefined) {
			void Promise.resolve(result).catch(() => undefined);
			throw new TypeError("preference authority must be synchronous");
		}
	};
	const binding = [claims.installation, claims.receiver, claims.epoch, claims.incarnation, claims.expiry, claims.key_fingerprint];
	if (claims.action === "preference-read") {
		check();
		return db.prepare(`SELECT ${receipt} FROM watch_lifecycle_preference WHERE ${current}`)
			.bind(...binding).first<PreferenceReceipt>();
	}
	if (claims.action !== "preference-write" || claims.expected_version === undefined
		|| claims.expected_version >= Number.MAX_SAFE_INTEGER) return null;
	const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", original)),
		byte => byte.toString(16).padStart(2, "0")).join("");
	const parameters = [...binding, claims.expected_version, claims.operation, Number(claims.enabled), hash];
	const available = `(SELECT count(*) FROM watch_lifecycle_intent WHERE ${intentScope}) < ?11`;
	const statements = [
		db.prepare(`UPDATE watch_lifecycle_preference
			SET revision=revision+1, operation=?8, enabled=?9, body_hash=?10,
				sealed=CASE WHEN ${available} THEN 0 ELSE 1 END
			WHERE ${current} AND revision=?7 AND sealed=0
			AND (?9=0 OR ${available})
			AND NOT EXISTS (SELECT 1 FROM watch_lifecycle_intent WHERE ${intentScope} AND operation=?8)
			RETURNING ${receipt}`).bind(...parameters, capacity),
		db.prepare(`SELECT ${receipt} FROM watch_lifecycle_preference
			WHERE ${current} AND revision=?7+1 AND operation=?8 AND enabled=?9 AND body_hash=?10 AND sealed=0`)
			.bind(...parameters),
	];
	check();
	const [write, replay] = await db.batch<PreferenceReceipt>(statements);
	return write?.results[0] ?? replay?.results[0] ?? null;
}
