import { summarizeApiDiagnostics } from "./apiDiagnostics";
import type { AdminDiagnostics, ClientType } from "../types";

export async function getAdminDiagnostics(db: D1Database, sinceHours: number): Promise<AdminDiagnostics> {
	const since = `-${sinceHours} hours`;
	const [registrations, registrationErrors, relay, apnsFailures, api] = await Promise.all([
		summarizeRegistrations(db),
		summarizeRegistrationErrors(db),
		summarizeRelay(db, since),
		summarizeApnsFailures(db, since),
		summarizeApiDiagnostics(db, sinceHours),
	]);
	return {
		ok: true,
		generated_at: new Date().toISOString(),
		window_hours: sinceHours,
		registrations,
		registration_errors: registrationErrors,
		relay,
		apns_failures: apnsFailures,
		api,
	};
}

async function summarizeRegistrations(db: D1Database): Promise<AdminDiagnostics["registrations"]> {
	const totals = await db.prepare(`
		SELECT
			COUNT(*) AS total,
			SUM(CASE WHEN disabled = 0 AND invalid = 0 THEN 1 ELSE 0 END) AS active,
			SUM(CASE WHEN disabled = 1 THEN 1 ELSE 0 END) AS disabled,
			SUM(CASE WHEN invalid = 1 THEN 1 ELSE 0 END) AS invalid
		FROM registrations
	`).first<RegistrationTotalsRow>();

	const byClient = await db.prepare(`
		SELECT client_type, apns_environment, disabled, invalid, COUNT(*) AS count
		FROM registrations
		GROUP BY client_type, apns_environment, disabled, invalid
		ORDER BY count DESC, client_type ASC, apns_environment ASC
	`).all<RegistrationGroupRow>();

	return {
		total: totals?.total ?? 0,
		active: totals?.active ?? 0,
		disabled: totals?.disabled ?? 0,
		invalid: totals?.invalid ?? 0,
		by_client: (byClient.results ?? []).map((row) => ({
			client_type: row.client_type,
			apns_environment: row.apns_environment,
			disabled: row.disabled === 1,
			invalid: row.invalid === 1,
			count: row.count,
		})),
	};
}

async function summarizeRegistrationErrors(db: D1Database): Promise<AdminDiagnostics["registration_errors"]> {
	const result = await db.prepare(`
		SELECT last_error_code AS code, COUNT(*) AS count
		FROM registrations
		WHERE last_error_code IS NOT NULL
		GROUP BY last_error_code
		ORDER BY count DESC, code ASC
		LIMIT 25
	`).all<{ code: string; count: number }>();
	return result.results ?? [];
}

async function summarizeRelay(db: D1Database, since: string): Promise<AdminDiagnostics["relay"]> {
	const totals = await db.prepare(`
		SELECT
			COUNT(*) AS events,
			COALESCE(SUM(target_count), 0) AS targeted,
			COALESCE(SUM(success_count), 0) AS delivered,
			COALESCE(SUM(error_count), 0) AS failed
		FROM relay_events
		WHERE created_at >= datetime('now', ?)
	`).bind(since).first<RelayTotalsRow>();

	const byEvent = await db.prepare(`
		SELECT event_type, COALESCE(client_type, 'mixed') AS client_type,
			COUNT(*) AS events,
			COALESCE(SUM(target_count), 0) AS targeted,
			COALESCE(SUM(success_count), 0) AS delivered,
			COALESCE(SUM(error_count), 0) AS failed
		FROM relay_events
		WHERE created_at >= datetime('now', ?)
		GROUP BY event_type, client_type
		ORDER BY failed DESC, events DESC, event_type ASC
	`).bind(since).all<RelayGroupRow>();

	return {
		events: totals?.events ?? 0,
		targeted: totals?.targeted ?? 0,
		delivered: totals?.delivered ?? 0,
		failed: totals?.failed ?? 0,
		by_event: (byEvent.results ?? []).map((row) => ({
			event_type: row.event_type,
			client_type: parseClientType(row.client_type),
			events: row.events,
			targeted: row.targeted,
			delivered: row.delivered,
			failed: row.failed,
		})),
	};
}

async function summarizeApnsFailures(db: D1Database, since: string): Promise<AdminDiagnostics["apns_failures"]> {
	const result = await db.prepare(`
		SELECT apns_reason AS reason, apns_status AS status, COALESCE(client_type, 'mixed') AS client_type, SUM(count) AS count
		FROM push_delivery_failures
		WHERE created_at >= datetime('now', ?)
		GROUP BY apns_reason, apns_status, client_type
		ORDER BY count DESC, reason ASC
		LIMIT 50
	`).bind(since).all<ApnsFailureRow>();

	return (result.results ?? []).map((row) => ({
		reason: row.reason,
		status: row.status,
		client_type: parseClientType(row.client_type),
		count: row.count,
	}));
}

function parseClientType(value: string): ClientType | null {
	if (value === "ios" || value === "macos" || value === "watchos") return value;
	return null;
}

interface RegistrationTotalsRow {
	total: number;
	active: number | null;
	disabled: number | null;
	invalid: number | null;
}

interface RegistrationGroupRow {
	client_type: ClientType;
	apns_environment: "sandbox" | "production";
	disabled: number;
	invalid: number;
	count: number;
}

interface RelayTotalsRow {
	events: number;
	targeted: number;
	delivered: number;
	failed: number;
}

interface RelayGroupRow {
	event_type: string;
	client_type: string;
	events: number;
	targeted: number;
	delivered: number;
	failed: number;
}

interface ApnsFailureRow {
	reason: string;
	status: number;
	client_type: string;
	count: number;
}
