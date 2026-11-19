import { cryptoRandomId } from "../crypto";
import type { ClientType, EventType, PushFailureSummary } from "../types";

export async function purgePushDeliveryDiagnostics(db: D1Database, now = Date.now()): Promise<void> {
	const cutoff = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 19).replace("T", " ");
	await db.batch([
		db.prepare("DELETE FROM push_delivery_failures WHERE created_at <= ?").bind(cutoff),
		db.prepare(`DELETE FROM push_delivery_failures
			WHERE relay_event_id IN (SELECT id FROM relay_events WHERE created_at <= ?)`).bind(cutoff),
		db.prepare("DELETE FROM relay_events WHERE created_at <= ?").bind(cutoff),
		db.prepare("UPDATE registrations SET last_success_at = NULL WHERE last_success_at <= ?").bind(cutoff),
		db.prepare(`UPDATE registrations SET last_error_code = NULL
			WHERE last_error_code IS NOT NULL AND updated_at <= ?`).bind(cutoff),
	]);
}

export async function auditEvent(db: D1Database, input: { ha_install_id: string; event_type: EventType; client_type?: ClientType; target: number; success: number; error: number; failures?: PushFailureSummary[] }): Promise<void> {
	const relayEventId = cryptoRandomId();
	await db.prepare(`
		INSERT INTO relay_events (id, ha_install_id, event_type, client_type, target_count, success_count, error_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`).bind(
		relayEventId,
		input.ha_install_id,
		input.event_type,
		input.client_type ?? null,
		input.target,
		input.success,
		input.error,
	).run();

	for (const failure of input.failures ?? []) {
		await db.prepare(`
			INSERT INTO push_delivery_failures (id, relay_event_id, client_type, apns_status, apns_reason, count, created_at)
			VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
		`).bind(
			cryptoRandomId(),
			relayEventId,
			failure.client_type,
			failure.status,
			failure.reason,
			failure.count,
		).run();
	}
}
