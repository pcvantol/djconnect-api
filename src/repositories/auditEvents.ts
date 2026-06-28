import { cryptoRandomId } from "../crypto";
import type { ClientType, EventType } from "../types";

export async function auditEvent(db: D1Database, input: { ha_install_id: string; event_type: EventType; client_type?: ClientType; target: number; success: number; error: number }): Promise<void> {
	await db.prepare(`
		INSERT INTO relay_events (id, ha_install_id, event_type, client_type, target_count, success_count, error_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`).bind(
		cryptoRandomId(),
		input.ha_install_id,
		input.event_type,
		input.client_type ?? null,
		input.target,
		input.success,
		input.error,
	).run();
}
