import { cryptoRandomId, cryptoRandomToken, sha256Hex } from "../crypto";
import type { InstallTokenRecord, InstallTokenRequest, RevokeInstallTokenRequest } from "../types";

async function prepareInstallToken(db: D1Database, input: InstallTokenRequest, currentTokenId?: string) {
	const id = cryptoRandomId();
	const token = cryptoRandomToken("djci");
	const tokenHash = await sha256Hex(token);
	const parameters = [id, input.ha_install_id, input.ha_user_hash ?? null, tokenHash, token.slice(0, 12), input.label ?? null];

	const insert = db.prepare(`
		INSERT INTO install_tokens (
			id, ha_install_id, ha_user_hash, token_hash, token_prefix,
			label, disabled, created_at, updated_at
		)
		SELECT ?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now')
		${currentTokenId === undefined ? "" : `WHERE EXISTS (
			SELECT 1 FROM install_tokens WHERE id = ? AND ha_install_id = ? AND disabled = 0
		)`}
	`).bind(...parameters, ...(currentTokenId === undefined ? [] : [currentTokenId, input.ha_install_id]));

	return { credential: { id, token, tokenHash }, insert };
}

export async function issueInstallToken(db: D1Database, input: InstallTokenRequest): Promise<{ id: string; token: string; tokenHash: string }> {
	const { credential, insert } = await prepareInstallToken(db, input);
	await insert.run();
	return credential;
}

export async function rotateInstallToken(db: D1Database, input: InstallTokenRequest, currentTokenId: string) {
	const { credential, insert } = await prepareInstallToken(db, input, currentTokenId);
	// Retire the old tokens only if this batch inserted the replacement.
	const retire = db.prepare(`
		UPDATE install_tokens
		SET disabled = 1, rotated_at = datetime('now'), updated_at = datetime('now')
		WHERE ha_install_id = ? AND disabled = 0 AND id <> ?
			AND EXISTS (SELECT 1 FROM install_tokens WHERE id = ? AND token_hash = ?)
	`).bind(input.ha_install_id, credential.id, credential.id, credential.tokenHash);

	const [created] = await db.batch([insert, retire]);
	return created.meta.changes === 1 ? credential : null;
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
