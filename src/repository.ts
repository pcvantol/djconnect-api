import { cryptoRandomId, cryptoRandomToken, encryptSecret, sha256Hex } from "./crypto";
import { timingSafeEqualString } from "./crypto";
import { HttpError } from "./http";
import type { AdminRegistration, AdminRegistrationsQuery, ApnsEnvironment, BootstrapProofRequest, ClientType, EventType, InstallTokenRecord, InstallTokenRequest, PushEventRequest, RegisterRequest, Registration, UnregisterRequest } from "./types";

export function topicForClientType(env: { APNS_TOPIC_IOS: string; APNS_TOPIC_MACOS: string; APNS_TOPIC_WATCHOS: string }, clientType: ClientType): string {
	switch (clientType) {
		case "ios":
			return env.APNS_TOPIC_IOS;
		case "macos":
			return env.APNS_TOPIC_MACOS;
		case "watchos":
			return env.APNS_TOPIC_WATCHOS;
	}
}

export async function upsertRegistration(db: D1Database, env: { APNS_TOPIC_IOS: string; APNS_TOPIC_MACOS: string; APNS_TOPIC_WATCHOS: string; APNS_ENVIRONMENT: ApnsEnvironment; APNS_TOKEN_ENCRYPTION_KEY: string }, input: RegisterRequest): Promise<{ id: string; tokenHash: string }> {
	const tokenHash = await sha256Hex(input.apns_token);
	const encryptedToken = await encryptSecret(input.apns_token, env.APNS_TOKEN_ENCRYPTION_KEY);
	const id = cryptoRandomId();
	const apnsEnvironment = input.apns_environment ?? env.APNS_ENVIRONMENT;
	const topic = topicForClientType(env, input.client_type);
	const categories = JSON.stringify(input.categories ?? []);

	await db.prepare(`
		INSERT INTO registrations (
			id, ha_install_id, ha_user_hash, device_id, client_type, apns_token_hash,
			apns_token, apns_token_ciphertext, apns_token_nonce, apns_token_key_version,
			apns_environment, topic, app_bundle_id,
			app_version, locale, categories_json, disabled, invalid, created_at, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, datetime('now'), datetime('now'))
		ON CONFLICT(ha_install_id, device_id, client_type, apns_token_hash) DO UPDATE SET
			ha_user_hash = excluded.ha_user_hash,
			apns_token = excluded.apns_token,
			apns_token_ciphertext = excluded.apns_token_ciphertext,
			apns_token_nonce = excluded.apns_token_nonce,
			apns_token_key_version = excluded.apns_token_key_version,
			apns_environment = excluded.apns_environment,
			topic = excluded.topic,
			app_bundle_id = excluded.app_bundle_id,
			app_version = excluded.app_version,
			locale = excluded.locale,
			categories_json = excluded.categories_json,
			disabled = 0,
			invalid = 0,
			updated_at = datetime('now'),
			last_error_code = NULL
	`).bind(
		id,
		input.ha_install_id,
		input.ha_user_hash ?? null,
		input.device_id,
		input.client_type,
		tokenHash,
		encryptedToken.ciphertext,
		encryptedToken.nonce,
		encryptedToken.keyVersion,
		apnsEnvironment,
		topic,
		input.app_bundle_id ?? null,
		input.app_version ?? null,
		input.locale ?? null,
		categories,
	).run();

	return { id, tokenHash };
}

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

export async function rotateInstallToken(db: D1Database, input: InstallTokenRequest): Promise<{ id: string; token: string; tokenHash: string }> {
	await db.prepare(`
		UPDATE install_tokens
		SET disabled = 1, rotated_at = datetime('now'), updated_at = datetime('now')
		WHERE ha_install_id = ? AND disabled = 0
	`).bind(input.ha_install_id).run();
	return issueInstallToken(db, input);
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

export async function unregister(db: D1Database, input: UnregisterRequest): Promise<number> {
	let statement = "UPDATE registrations SET disabled = 1, updated_at = datetime('now') WHERE ha_install_id = ? AND device_id = ?";
	const params: string[] = [input.ha_install_id, input.device_id];
	if (input.client_type) {
		statement += " AND client_type = ?";
		params.push(input.client_type);
	}
	if (input.apns_token) {
		statement += " AND apns_token_hash = ?";
		params.push(await sha256Hex(input.apns_token));
	}
	const result = await db.prepare(statement).bind(...params).run();
	return result.meta.changes ?? 0;
}

export async function findActiveRegistrations(db: D1Database, input: PushEventRequest): Promise<Registration[]> {
	let statement = "SELECT * FROM registrations WHERE ha_install_id = ? AND disabled = 0 AND invalid = 0";
	const params: string[] = [input.ha_install_id];
	if (input.ha_user_hash) {
		statement += " AND ha_user_hash = ?";
		params.push(input.ha_user_hash);
	}
	if (input.client_types?.length) {
		statement += ` AND client_type IN (${input.client_types.map(() => "?").join(", ")})`;
		params.push(...input.client_types);
	}
	const result = await db.prepare(statement).bind(...params).all<Registration>();
	return result.results ?? [];
}

export async function listAdminRegistrations(db: D1Database, query: AdminRegistrationsQuery): Promise<{ registrations: AdminRegistration[]; next_offset: number | null }> {
	const clauses: string[] = [];
	const params: Array<string | number> = [];

	if (query.client_type) {
		clauses.push("client_type = ?");
		params.push(query.client_type);
	}
	if (query.apns_environment) {
		clauses.push("apns_environment = ?");
		params.push(query.apns_environment);
	}
	if (query.disabled !== undefined) {
		clauses.push("disabled = ?");
		params.push(query.disabled ? 1 : 0);
	}
	if (query.invalid !== undefined) {
		clauses.push("invalid = ?");
		params.push(query.invalid ? 1 : 0);
	}
	if (query.ha_install_id) {
		clauses.push("ha_install_id = ?");
		params.push(query.ha_install_id);
	}

	const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
	const result = await db.prepare(`
		SELECT
			id, ha_install_id, ha_user_hash, device_id, client_type, apns_token_hash,
			apns_environment, topic, app_bundle_id, app_version, locale, categories_json,
			disabled, invalid, created_at, updated_at, last_success_at, last_error_code
		FROM registrations
		${where}
		ORDER BY updated_at DESC, id ASC
		LIMIT ? OFFSET ?
	`).bind(...params, query.limit + 1, query.offset).all<AdminRegistrationRow>();

	const rows = result.results ?? [];
	const page = rows.slice(0, query.limit);
	return {
		registrations: await Promise.all(page.map(redactAdminRegistration)),
		next_offset: rows.length > query.limit ? query.offset + query.limit : null,
	};
}

interface AdminRegistrationRow {
	id: string;
	ha_install_id: string;
	ha_user_hash: string | null;
	device_id: string;
	client_type: ClientType;
	apns_token_hash: string | null;
	apns_environment: ApnsEnvironment;
	topic: string;
	app_bundle_id: string | null;
	app_version: string | null;
	locale: string | null;
	categories_json: string | null;
	disabled: number;
	invalid: number;
	created_at: string;
	updated_at: string;
	last_success_at: string | null;
	last_error_code: string | null;
}

async function redactAdminRegistration(row: AdminRegistrationRow): Promise<AdminRegistration> {
	return {
		id: row.id,
		ha_install_id_hash: await stableHashPrefix(row.ha_install_id),
		ha_user_hash: row.ha_user_hash,
		device_id_hash: await stableHashPrefix(row.device_id),
		client_type: row.client_type,
		apns_environment: row.apns_environment,
		topic: row.topic,
		app_bundle_id: row.app_bundle_id,
		app_version: row.app_version,
		locale: row.locale,
		categories: parseCategories(row.categories_json),
		disabled: row.disabled === 1,
		invalid: row.invalid === 1,
		created_at: row.created_at,
		updated_at: row.updated_at,
		last_success_at: row.last_success_at,
		last_error_code: row.last_error_code,
		apns_token_hash_prefix: row.apns_token_hash ? row.apns_token_hash.slice(0, 12) : null,
	};
}

async function stableHashPrefix(value: string): Promise<string> {
	return (await sha256Hex(value)).slice(0, 16);
}

function parseCategories(value: string | null): string[] {
	if (!value) return [];
	try {
		const parsed = JSON.parse(value) as unknown;
		return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
	} catch {
		return [];
	}
}

export async function markRegistrationSuccess(db: D1Database, id: string): Promise<void> {
	await db.prepare("UPDATE registrations SET last_success_at = datetime('now'), last_error_code = NULL, updated_at = datetime('now') WHERE id = ?").bind(id).run();
}

export async function markRegistrationError(db: D1Database, id: string, code: string, disable: boolean): Promise<void> {
	await db.prepare(`
		UPDATE registrations
		SET last_error_code = ?, disabled = CASE WHEN ? THEN 1 ELSE disabled END,
			invalid = CASE WHEN ? THEN 1 ELSE invalid END, updated_at = datetime('now')
		WHERE id = ?
	`).bind(code, disable ? 1 : 0, disable ? 1 : 0, id).run();
}

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
