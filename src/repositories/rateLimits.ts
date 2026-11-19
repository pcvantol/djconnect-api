import { HttpError } from "../http";
import { stableHashPrefix } from "./hash";

export async function enforceBootstrapRateLimit(db: D1Database, input: { ip: string; ha_install_id: string; device_id: string }): Promise<void> {
	const windowSeconds = 10 * 60;
	await checkRateLimit(db, `bootstrap:ip:${await stableHashPrefix(input.ip)}`, 30, windowSeconds);
	await checkRateLimit(db, `bootstrap:install:${await stableHashPrefix(input.ha_install_id)}`, 10, windowSeconds);
	await checkRateLimit(db, `bootstrap:device:${await stableHashPrefix(input.device_id)}`, 10, windowSeconds);
}

async function checkRateLimit(db: D1Database, key: string, maxCount: number, windowSeconds: number): Promise<void> {
	const now = Math.floor(Date.now() / 1000);
	const row = await db.prepare(`
		SELECT window_start, count
		FROM bootstrap_rate_limits
		WHERE key = ?
	`).bind(key).first<{ window_start: number; count: number }>();

	if (!row || now - row.window_start >= windowSeconds) {
		await db.prepare(`
			INSERT INTO bootstrap_rate_limits (key, window_start, count, updated_at)
			VALUES (?, ?, 1, datetime('now'))
			ON CONFLICT(key) DO UPDATE SET
				window_start = excluded.window_start,
				count = excluded.count,
				updated_at = datetime('now')
		`).bind(key, now).run();
		return;
	}

	if (row.count >= maxCount) {
		throw new HttpError(429, "bootstrap_rate_limited");
	}

	await db.prepare(`
		UPDATE bootstrap_rate_limits
		SET count = count + 1, updated_at = datetime('now')
		WHERE key = ?
	`).bind(key).run();
}
