import { cryptoRandomId } from "../crypto";
import type { ClientType, EventType, PushFailureSummary } from "../types";

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
