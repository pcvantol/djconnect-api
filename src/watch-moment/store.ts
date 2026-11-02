import type { Registration } from "../types";

export type State = "reserved" | "dispatching" | "provider_accepted" | "provider_rejected" | "retryable" | "unknown" | "cancelled" | "expired";
export interface Operation {
	operation_key: string; publication_key: string; scope_hash: string; recipient_hash: string; request_hash: string;
	registration_hash: string; state: State; created_at_ms: number; expires_at_ms: number;
	lease_id: string; attempts: number; next_attempt_ms: number; provider_status: number | null;
}
export interface Limits { capacity: number; installationCapacity: number; recipientBurst: number }

export class MomentStore {
	constructor(private readonly db: D1Database) {}
	get(key: string) { return this.db.prepare("SELECT * FROM watch_moment_operations WHERE operation_key=?").bind(key).first<Operation>(); }
	publication(key: string) { return this.db.prepare("SELECT * FROM watch_moment_operations WHERE publication_key=?").bind(key).first<Operation>(); }
	async current(registration: Registration, active: boolean, originalCipher = false) {
		const actual = await this.db.prepare("SELECT * FROM registrations WHERE id=?").bind(registration.id).first<Registration>();
		if (!actual) return false;
		for (const key of ["id", "ha_install_id", "ha_user_hash", "device_id", "client_type", "apns_token_hash", "topic", "app_bundle_id", "apns_environment"] as const) {
			if (actual[key] !== registration[key]) return false;
		}
		if (originalCipher && (actual.apns_token_ciphertext !== registration.apns_token_ciphertext || actual.apns_token_nonce !== registration.apns_token_nonce)) return false;
		return !active || (actual.disabled === 0 && actual.invalid === 0 && actual.categories_json === registration.categories_json);
	}
	async reserve(row: Operation, limits: Limits, cancellation = false) {
		await this.db.prepare(`INSERT INTO watch_moment_operations
		 (operation_key,publication_key,scope_hash,recipient_hash,request_hash,registration_hash,state,created_at_ms,expires_at_ms,lease_id,attempts,next_attempt_ms,provider_status)
		 SELECT ?,?,?,?,?,?,?,?,?,?,1,?,NULL
		 WHERE (SELECT count(*) FROM watch_moment_operations) < ?
		 AND (SELECT count(*) FROM watch_moment_operations WHERE scope_hash=?) < ?
		 AND (?=1 OR (SELECT count(*) FROM watch_moment_operations WHERE recipient_hash=? AND created_at_ms>=?) < ?)
		 ON CONFLICT DO NOTHING`).bind(row.operation_key, row.publication_key, row.scope_hash, row.recipient_hash,
			row.request_hash, row.registration_hash, row.state, row.created_at_ms, row.expires_at_ms, row.lease_id, row.created_at_ms,
			limits.capacity - (cancellation ? 0 : 1), row.scope_hash, limits.installationCapacity - (cancellation ? 0 : 1),
			cancellation ? 1 : 0, row.recipient_hash, row.created_at_ms - 600_000, limits.recipientBurst).run();
		return (await this.get(row.operation_key)) ?? this.publication(row.publication_key);
	}
	async retry(row: Operation, lease: string, now: number) {
		const r = await this.db.prepare(`UPDATE watch_moment_operations SET state='reserved',lease_id=?,attempts=attempts+1
		 WHERE operation_key=? AND request_hash=? AND registration_hash=? AND state='retryable'
		 AND attempts<3 AND next_attempt_ms<=? AND expires_at_ms>?`).bind(lease, row.operation_key, row.request_hash, row.registration_hash, now, now).run();
		return (r.meta.changes ?? 0) === 1;
	}
	async mark(row: Operation, now: number, r: Registration) {
		const result = await this.db.prepare(`UPDATE watch_moment_operations SET state='dispatching'
		 WHERE operation_key=? AND lease_id=? AND state='reserved' AND expires_at_ms>?
		 AND EXISTS(SELECT 1 FROM registrations WHERE id=? AND ha_install_id=? AND ha_user_hash=? AND device_id=?
		 AND client_type='watchos' AND apns_token_hash=? AND topic=? AND app_bundle_id=? AND apns_environment=?
		 AND categories_json=? AND disabled=0 AND invalid=0)`)
			.bind(row.operation_key, row.lease_id, now, r.id, r.ha_install_id, r.ha_user_hash, r.device_id,
				r.apns_token_hash, r.topic, r.app_bundle_id, r.apns_environment, r.categories_json).run();
		return (result.meta.changes ?? 0) === 1;
	}
	async finish(row: Operation, state: State, status: number | null, next: number) {
		await this.db.prepare(`UPDATE watch_moment_operations SET state=?,provider_status=?,next_attempt_ms=?
		 WHERE operation_key=? AND lease_id=? AND state IN ('reserved','dispatching')`).bind(state, status, next, row.operation_key, row.lease_id).run();
	}
	async cancel(key: string, requestHash: string, registrationHash: string) {
		await this.db.prepare(`UPDATE watch_moment_operations SET state='cancelled'
		 WHERE operation_key=? AND request_hash=? AND registration_hash=? AND state IN ('reserved','retryable')`).bind(key, requestHash, registrationHash).run();
	}
}
