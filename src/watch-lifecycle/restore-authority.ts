import { watchDispatchScopeBinding, type WatchDispatchScope } from "./dispatch-identity";

interface PreferenceState {
	revision: number;
	operation: string | null;
	body_hash: string | null;
	enabled: number;
	sealed: number;
}

const disabledBaseline = JSON.stringify([0, null, null, 0, 0]);

function stateKey(state: PreferenceState): string | null {
	const { revision, operation, body_hash, enabled, sealed } = state;
	if (!Number.isSafeInteger(revision) || revision < 0 ||
		(enabled !== 0 && enabled !== 1) || (sealed !== 0 && sealed !== 1) ||
		(sealed === 1 && enabled === 1)) return null;
	if (revision === 0) {
		if (operation !== null || body_hash !== null || enabled !== 0 || sealed !== 0) return null;
	} else if (typeof operation !== "string" || !/^[A-Za-z0-9._~-]{1,160}$/.test(operation) ||
		typeof body_hash !== "string" || !/^[a-f0-9]{64}$/.test(body_hash)) return null;
	return JSON.stringify([revision, operation, body_hash, enabled, sealed]);
}

/** Lives in the owning dispatch actor, outside D1 restores. Only admitted callers may use it. */
export class WatchRestoreAuthority {
	constructor(private readonly storage: DurableObjectStorage) {
		storage.sql.exec(`CREATE TABLE IF NOT EXISTS watch_restore_authority (
			id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL,
			confirmed TEXT NOT NULL, pending TEXT
		)`);
	}

	/** Only for a newly enrolled incarnation, never as a repair for missing authority. */
	initializeDisabled(scope: WatchDispatchScope): boolean {
		const binding = watchDispatchScopeBinding(scope);
		if (binding === null) return false;
		return this.storage.sql.exec(
			"INSERT OR IGNORE INTO watch_restore_authority VALUES (1,?,?,NULL) RETURNING id",
			binding, disabledBaseline,
		).toArray().length === 1;
	}

	/** Only for independently approved enrollment; a generation change begins disabled. */
	advanceGeneration(previous: WatchDispatchScope, next: WatchDispatchScope): boolean {
		const before = watchDispatchScopeBinding(previous);
		const after = watchDispatchScopeBinding(next);
		if (before === null || after === null || previous.installation !== next.installation ||
			previous.receiver !== next.receiver || next.epoch <= previous.epoch ||
			next.incarnation === previous.incarnation) return false;
		return this.storage.sql.exec(`UPDATE watch_restore_authority SET scope=?1,confirmed=?2
			WHERE id=1 AND scope=?3 AND pending IS NULL RETURNING id`, after, disabledBaseline, before).toArray().length === 1;
	}

	/** Persist the exact transition before the caller may submit its D1 CAS. */
	async begin(scope: WatchDispatchScope, previous: PreferenceState, next: PreferenceState): Promise<boolean> {
		const binding = watchDispatchScopeBinding(scope);
		const predecessor = stateKey(previous);
		const pending = stateKey(next);
		if (binding === null || predecessor === null || pending === null ||
			previous.sealed === 1 || next.revision !== previous.revision + 1) return false;
		const matched = this.storage.sql.exec(`UPDATE watch_restore_authority SET pending=?1
			WHERE id=1 AND scope=?2 AND confirmed=?3 AND (pending IS NULL OR pending=?1) RETURNING id`,
			pending, binding, predecessor).toArray().length === 1;
		if (matched) await this.storage.sync();
		return matched;
	}

	/** Only an exact D1 readback of the reserved transition can clear uncertainty. */
	confirm(scope: WatchDispatchScope, observed: PreferenceState): boolean {
		const binding = watchDispatchScopeBinding(scope);
		const state = stateKey(observed);
		if (binding === null || state === null) return false;
		return this.storage.sql.exec(`UPDATE watch_restore_authority SET confirmed=?1,pending=NULL
			WHERE id=1 AND scope=?2 AND pending=?1 RETURNING id`, state, binding).toArray().length === 1;
	}

	/** Invoke the prepared provider entry in this same actor turn, with no intervening await. */
	start<T>(scope: WatchDispatchScope, observed: PreferenceState, enterProvider: () => T): { result: T } | null {
		const binding = watchDispatchScopeBinding(scope);
		const state = stateKey(observed);
		const allowed = binding !== null && state !== null && observed.enabled === 1 &&
			this.storage.sql.exec(`SELECT 1 FROM watch_restore_authority
				WHERE id=1 AND scope=? AND confirmed=? AND pending IS NULL`, binding, state).toArray().length === 1;
		return allowed ? { result: enterProvider() } : null;
	}
}
