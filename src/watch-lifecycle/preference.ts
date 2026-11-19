import type { WatchRestoreAuthority, WatchPreferenceState } from "./restore-authority";
import { runWatchRestoreTransition } from "./restore-transition";
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
	db: D1Database, body: Uint8Array, signature: Uint8Array, expectedSpki: Uint8Array, audience: string, now: number, assertCurrent: (claims: LifecycleClaims) => void, restore?: WatchRestoreAuthority,
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
		if (!restore) return db.prepare(`SELECT ${receipt} FROM watch_lifecycle_preference WHERE ${current}`)
			.bind(...binding).first<PreferenceReceipt>();
		const observed = await db.prepare(`SELECT ${receipt},body_hash FROM watch_lifecycle_preference WHERE ${current}`)
			.bind(...binding).first<PreferenceReceipt & { body_hash: string | null }>();
		check();
		if (!observed || restore.classifyObservation(claims, observed) !== "confirmed") return null;
		const { body_hash: _, ...confirmed } = observed;
		return confirmed;
	}
	if (claims.action !== "preference-write" || claims.expected_version === undefined
		|| claims.expected_version >= Number.MAX_SAFE_INTEGER) return null;
	const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", original)),
		byte => byte.toString(16).padStart(2, "0")).join("");
	const parameters = [...binding, claims.expected_version, claims.operation, Number(claims.enabled), hash];
	const available = `(SELECT count(*) FROM watch_lifecycle_intent WHERE ${intentScope}) < ?11`;
	const update = (previous?: WatchPreferenceState, sealed?: number) => db.prepare(`UPDATE watch_lifecycle_preference
			SET revision=revision+1, operation=?8, enabled=?9, body_hash=?10,
				sealed=CASE WHEN ${available} THEN 0 ELSE 1 END
			WHERE ${current} AND revision=?7 AND sealed=0
			AND (?9=0 OR ${available})
			AND NOT EXISTS (SELECT 1 FROM watch_lifecycle_intent WHERE ${intentScope} AND operation=?8)
			${previous ? `AND operation IS ?12 AND body_hash IS ?13 AND enabled=?14
				AND CASE WHEN ${available} THEN 0 ELSE 1 END = ?15` : ""}
			RETURNING ${receipt}`).bind(...parameters, capacity,
				...(previous ? [previous.operation, previous.body_hash, previous.enabled, sealed] : []));
	if (restore) {
		const readback = () => db.prepare(`SELECT revision,operation,body_hash,enabled,sealed,
			(SELECT count(*) FROM watch_lifecycle_intent WHERE ${intentScope}) AS intent_count
			FROM watch_lifecycle_preference WHERE ${current}`).bind(...binding)
			.first<WatchPreferenceState & { intent_count: number }>();
		check();
		const observed = await readback();
		if (!observed) return null;
		const replay = observed.revision === claims.expected_version + 1 &&
			observed.operation === claims.operation && observed.body_hash === hash &&
			observed.enabled === Number(claims.enabled);
		const next = {
			revision: claims.expected_version + 1, operation: claims.operation, body_hash: hash,
			enabled: Number(claims.enabled), sealed: replay ? observed.sealed : Number(observed.intent_count >= capacity),
		};
		if (next.enabled === 1 && next.sealed === 1) return null;
		const result = await runWatchRestoreTransition(restore, claims, claims.expected_version, next, {
			readback, assertCurrent: check, submit: previous => update(previous, next.sealed).first(),
		});
		if (result === "unknown") throw new Error("Watch preference restore outcome unknown");
		return result === "confirmed" ? {
			incarnation: claims.incarnation, revision: next.revision, operation: next.operation,
			enabled: next.enabled, sealed: next.sealed,
		} : null;
	}
	const statements = [
		update(),
		db.prepare(`SELECT ${receipt} FROM watch_lifecycle_preference
			WHERE ${current} AND revision=?7+1 AND operation=?8 AND enabled=?9 AND body_hash=?10 AND sealed=0`)
			.bind(...parameters),
	];
	check();
	const [write, replay] = await db.batch<PreferenceReceipt>(statements);
	return write?.results[0] ?? replay?.results[0] ?? null;
}
