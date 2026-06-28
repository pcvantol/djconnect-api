import { cryptoRandomId, cryptoRandomToken, sha256Hex, timingSafeEqualString } from "../crypto";
import { HttpError } from "../http";
import type { BootstrapProofRequest, InstallTokenRequest } from "../types";

export async function issueBootstrapProof(db: D1Database, input: BootstrapProofRequest): Promise<{ id: string; proof: string; proofHash: string; expiresAt: string }> {
	const id = cryptoRandomId();
	const proof = cryptoRandomToken("djcboot");
	const proofHash = await sha256Hex(proof);
	const expiresAt = new Date(Date.now() + (input.ttl_seconds ?? 600) * 1000).toISOString();

	await db.prepare(`
		INSERT INTO bootstrap_proofs (
			id, proof_hash, ha_install_id, integration, integration_version,
			client_type, device_id, pairing_session_id, expires_at, created_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
	`).bind(
		id,
		proofHash,
		input.ha_install_id,
		input.integration ?? null,
		input.integration_version ?? null,
		input.client_type,
		input.device_id,
		input.pairing_session_id ?? null,
		expiresAt,
	).run();

	return { id, proof, proofHash, expiresAt };
}

export async function consumeBootstrapProof(db: D1Database, input: InstallTokenRequest): Promise<void> {
	if (!input.bootstrap_proof || !input.client_type || !input.device_id) {
		throw new HttpError(401, "invalid_bootstrap_proof");
	}

	const proofHash = await sha256Hex(input.bootstrap_proof);
	const row = await db.prepare(`
		SELECT id, proof_hash, ha_install_id, client_type, device_id, expires_at, used_at
		FROM bootstrap_proofs
		WHERE proof_hash = ?
		LIMIT 1
	`).bind(proofHash).first<{
		id: string;
		proof_hash: string;
		ha_install_id: string;
		client_type: string;
		device_id: string;
		expires_at: string;
		used_at: string | null;
	}>();

	if (!row || !(await timingSafeEqualString(row.proof_hash, proofHash))) {
		throw new HttpError(401, "invalid_bootstrap_proof");
	}
	if (row.used_at) {
		throw new HttpError(409, "bootstrap_proof_used");
	}
	if (Date.parse(row.expires_at) <= Date.now()) {
		throw new HttpError(401, "bootstrap_proof_expired");
	}
	if (!(await timingSafeEqualString(row.ha_install_id, input.ha_install_id))) {
		throw new HttpError(403, "install_id_mismatch");
	}
	if (!(await timingSafeEqualString(row.client_type, input.client_type))) {
		throw new HttpError(401, "invalid_bootstrap_proof");
	}
	if (!(await timingSafeEqualString(row.device_id, input.device_id))) {
		throw new HttpError(401, "invalid_bootstrap_proof");
	}

	const result = await db.prepare(`
		UPDATE bootstrap_proofs
		SET used_at = datetime('now')
		WHERE id = ? AND used_at IS NULL
	`).bind(row.id).run();
	if ((result.meta.changes ?? 0) !== 1) {
		throw new HttpError(409, "bootstrap_proof_used");
	}
}
