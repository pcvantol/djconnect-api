import { cryptoRandomId, cryptoRandomToken, sha256Hex } from "../crypto";
import type { InstallTokenRecord, InstallTokenRequest, RevokeInstallTokenRequest } from "../types";

export async function issueInstallToken(db: D1Database, input: InstallTokenRequest): Promise<{ id: string; token: string; tokenHash: string }> {
	const id = cryptoRandomId();
	const token = cryptoRandomToken("djci");
	const tokenHash = await sha256Hex(token);
	const tokenPrefix = token.slice(0, 12);

	await db.prepare(`
		INSERT INTO install_tokens (
			id, ha_install_id, ha_user_hash, token_hash, token_prefix,
			label, disabled, created_at, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
	`).bind(
		id,
		input.ha_install_id,
		input.ha_user_hash ?? null,
		tokenHash,
		tokenPrefix,
		input.label ?? null,
	).run();

	return { id, token, tokenHash };
}

export async function rotateInstallToken(db: D1Database, input: InstallTokenRequest): Promise<{ id: string; token: string; tokenHash: string }> {
	await db.prepare(`
		UPDATE install_tokens
		SET disabled = 1, rotated_at = datetime('now'), updated_at = datetime('now')
		WHERE ha_install_id = ? AND disabled = 0
	`).bind(input.ha_install_id).run();
	return issueInstallToken(db, input);
}

export async function revokeInstallToken(db: D1Database, input: RevokeInstallTokenRequest): Promise<{ revoked: number }> {
	const reason = input.reason?.trim() || null;
	const result = await db.prepare(`
		UPDATE install_tokens
		SET disabled = 1,
			revoked_at = COALESCE(revoked_at, datetime('now')),
			revoke_reason = ?,
			updated_at = datetime('now')
		WHERE id = ? AND ha_install_id = ? AND disabled = 0
	`).bind(reason, input.token_id, input.ha_install_id).run();
	return { revoked: result.meta.changes ?? 0 };
}

export async function findInstallTokenByBearer(db: D1Database, token: string): Promise<InstallTokenRecord | null> {
	const tokenHash = await sha256Hex(token);
	const row = await db.prepare(`
		SELECT * FROM install_tokens
		WHERE token_hash = ? AND disabled = 0
		LIMIT 1
	`).bind(tokenHash).first<InstallTokenRecord>();
	return row ?? null;
}

export async function markInstallTokenUsed(db: D1Database, id: string): Promise<void> {
	await db.prepare("UPDATE install_tokens SET last_used_at = datetime('now'), updated_at = datetime('now') WHERE id = ?").bind(id).run();
}
