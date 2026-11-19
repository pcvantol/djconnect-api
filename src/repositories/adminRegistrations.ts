import type { AdminRegistration, AdminRegistrationsQuery, ApnsEnvironment, ClientType } from "../types";
import { stableHashPrefix } from "./hash";

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

function parseCategories(value: string | null): string[] {
	if (!value) return [];
	try {
		const parsed = JSON.parse(value) as unknown;
		return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
	} catch {
		return [];
	}
}
