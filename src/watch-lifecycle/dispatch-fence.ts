import { MAX_TTL_MS } from "../watch-moment/wire";
import type { LifecycleClaims } from "./proof";

import { watchDispatchScopeBinding, type WatchDispatchScope as Scope } from "./dispatch-identity";

const id = /^[A-Za-z0-9._~-]{1,160}$/;
const digest = /^[a-f0-9]{64}$/;

/** Dispatch admission in the owning SQLite Durable Object for an exact enrolled scope. */
export class WatchDispatchFence {
	constructor(private readonly storage: DurableObjectStorage, private readonly scope: Readonly<Scope>) {
		this.scope = Object.freeze({ ...scope });
		storage.sql.exec(`CREATE TABLE IF NOT EXISTS watch_dispatch_fence (
			scope TEXT PRIMARY KEY NOT NULL,
			operation TEXT NOT NULL, body_hash TEXT NOT NULL
		)`);
		storage.sql.exec(`CREATE TABLE IF NOT EXISTS watch_dispatch_start (
			operation TEXT NOT NULL, lease TEXT NOT NULL, expires_at INTEGER NOT NULL,
			PRIMARY KEY(operation, lease)
		)`);
		storage.sql.exec(`CREATE TABLE IF NOT EXISTS watch_dispatch_clock (
			id INTEGER PRIMARY KEY CHECK (id = 1), high_water INTEGER NOT NULL
		)`);
	}

	private binding(claims: Scope): string | null {
		const binding = watchDispatchScopeBinding(claims);
		return binding === watchDispatchScopeBinding(this.scope) ? binding : null;
	}

	async block(claims: LifecycleClaims, bodyHash: string): Promise<boolean> {
		const scope = this.binding(claims);
		if (scope === null || claims.action !== "retire" || !id.test(claims.operation) || !digest.test(bodyHash)) return false;
		this.storage.sql.exec("INSERT OR IGNORE INTO watch_dispatch_fence VALUES (?,?,?)", scope, claims.operation, bodyHash);
		if (!this.hasBlock(claims, claims.operation, bodyHash)) return false;
		await this.storage.sync();
		return true;
	}

	hasBlock(claims: Scope, operation: string, bodyHash: string): boolean {
		const scope = this.binding(claims);
		return scope !== null && this.storage.sql.exec(
			"SELECT 1 FROM watch_dispatch_fence WHERE scope=? AND operation=? AND body_hash=?",
			scope, operation, bodyHash,
		).toArray().length === 1;
	}

	/** All authority checks and provider preparation precede this synchronous entry. */
	start<T>(
		claims: Scope, operation: string, lease: string, now: number, expiresAt: number,
		enterProvider: () => T,
	): { result: T } | null {
		const scope = this.binding(claims);
		if (scope === null || !digest.test(operation) || !id.test(lease) ||
			!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(expiresAt) ||
			expiresAt <= now || expiresAt - now > MAX_TTL_MS) return null;
		const sql = this.storage.sql;
		const admitted = this.storage.transactionSync(() => {
			if (sql.exec("SELECT 1 FROM watch_dispatch_fence WHERE scope=?", scope).toArray().length !== 0) return false;
			const clock = sql.exec<{ high_water: number }>("SELECT high_water FROM watch_dispatch_clock WHERE id=1").toArray()[0];
			if (clock && now < clock.high_water) return false;
			sql.exec("INSERT OR REPLACE INTO watch_dispatch_clock VALUES (1,?)", now);
			sql.exec("DELETE FROM watch_dispatch_start WHERE expires_at<=?", now);
			return sql.exec(`INSERT OR IGNORE INTO watch_dispatch_start
				SELECT ?,?,? WHERE (SELECT count(*) FROM watch_dispatch_start)<4096
				RETURNING operation`, operation, lease, expiresAt).toArray().length === 1;
		});
		return admitted ? { result: enterProvider() } : null;
	}
}
