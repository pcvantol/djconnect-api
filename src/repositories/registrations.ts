import { cryptoRandomId, encryptSecret, sha256Hex } from "../crypto";
import type { ApnsEnvironment, ClientType, PushEventRequest, RegisterRequest, Registration, UnregisterRequest } from "../types";

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
