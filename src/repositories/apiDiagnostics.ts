import { cryptoRandomId } from "../crypto";
import type { ApiDiagnosticSummary } from "../types";

export async function recordApiDiagnostic(db: D1Database, input: { method: string; route: string; status: number; error_code?: string }): Promise<void> {
	await db.prepare(`
		INSERT INTO api_diagnostics (id, method, route, status, error_code, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))
	`).bind(
		cryptoRandomId(),
		input.method,
		input.route,
		input.status,
		input.error_code ?? null,
	).run();
}

export async function summarizeApiDiagnostics(db: D1Database, sinceHours: number): Promise<ApiDiagnosticSummary> {
	const since = `-${sinceHours} hours`;
	const totals = await db.prepare(`
		SELECT
			COUNT(*) AS total,
			SUM(CASE WHEN status >= 200 AND status < 400 THEN 1 ELSE 0 END) AS ok,
			SUM(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) AS client_error,
			SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END) AS server_error
		FROM api_diagnostics
		WHERE created_at >= datetime('now', ?)
	`).bind(since).first<ApiDiagnosticTotalsRow>();

	const byRoute = await db.prepare(`
		SELECT method, route, status, COALESCE(error_code, '') AS error_code, COUNT(*) AS count
		FROM api_diagnostics
		WHERE created_at >= datetime('now', ?)
		GROUP BY method, route, status, error_code
		ORDER BY count DESC, route ASC, status ASC
		LIMIT 50
	`).bind(since).all<ApiDiagnosticRouteRow>();

	const byError = await db.prepare(`
		SELECT error_code, status, COUNT(*) AS count
		FROM api_diagnostics
		WHERE created_at >= datetime('now', ?)
			AND error_code IS NOT NULL
		GROUP BY error_code, status
		ORDER BY count DESC, error_code ASC
		LIMIT 50
	`).bind(since).all<ApiDiagnosticErrorRow>();

	return {
		window_hours: sinceHours,
		totals: {
			total: totals?.total ?? 0,
			ok: totals?.ok ?? 0,
			client_error: totals?.client_error ?? 0,
			server_error: totals?.server_error ?? 0,
		},
		by_route: (byRoute.results ?? []).map((row) => ({
			method: row.method,
			route: row.route,
			status: row.status,
			error_code: row.error_code || null,
			count: row.count,
		})),
		by_error: byError.results ?? [],
	};
}

interface ApiDiagnosticTotalsRow {
	total: number;
	ok: number | null;
	client_error: number | null;
	server_error: number | null;
}

interface ApiDiagnosticRouteRow {
	method: string;
	route: string;
	status: number;
	error_code: string;
	count: number;
}

interface ApiDiagnosticErrorRow {
	error_code: string;
	status: number;
	count: number;
}
