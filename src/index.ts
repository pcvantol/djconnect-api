import { sha256Hex } from "./crypto";
import { diagnostics, listRegistrations, revokeToken } from "./handlers/admin";
import { issueBootstrapProofHandler, issueInstallTokenHandler, rotateInstallTokenHandler } from "./handlers/install";
import { registerDevice, sendPushEvent, unregisterDevice } from "./handlers/push";
import { errorJson, HttpError, json } from "./http";
import { recordApiDiagnostic } from "./repository";
import type { AppEnv } from "./types";

type RouteHandler = (request: Request, env: AppEnv, ctx: ExecutionContext, url: URL) => Promise<Response>;

const routes: Array<{ method: string; path: string; handler: RouteHandler }> = [
	{
		method: "GET",
		path: "/v1/admin/diagnostics",
		handler: (request, env, _ctx, url) => diagnostics(request, env, url),
	},
	{
		method: "GET",
		path: "/v1/admin/registrations",
		handler: (request, env, _ctx, url) => listRegistrations(request, env, url),
	},
	{
		method: "POST",
		path: "/v1/operator/install-token/revoke",
		handler: (request, env) => revokeToken(request, env),
	},
	{
		method: "POST",
		path: "/v1/install/bootstrap-proof",
		handler: (request, env) => issueBootstrapProofHandler(request, env),
	},
	{
		method: "POST",
		path: "/v1/install/token",
		handler: (request, env) => issueInstallTokenHandler(request, env),
	},
	{
		method: "POST",
		path: "/v1/install/rotate",
		handler: (request, env) => rotateInstallTokenHandler(request, env),
	},
	{
		method: "POST",
		path: "/v1/push/register",
		handler: (request, env) => registerDevice(request, env),
	},
	{
		method: "POST",
		path: "/v1/push/unregister",
		handler: (request, env) => unregisterDevice(request, env),
	},
	{
		method: "POST",
		path: "/v1/push/event",
		handler: (request, env, ctx) => sendPushEvent(request, env, ctx),
	},
];

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const appEnv = env as AppEnv;
		const url = new URL(request.url);
		let routePath = url.pathname;
		try {
			const response = await route(request, appEnv, ctx);
			routePath = routePathFor(request.method, url.pathname);
			ctx.waitUntil(recordApiDiagnostic(appEnv.DB, {
				method: request.method,
				route: routePath,
				status: response.status,
			}));
			return response;
		} catch (error) {
			if (error instanceof HttpError) {
				const response = errorJson(request, error.code, { status: error.status });
				ctx.waitUntil(recordApiDiagnostic(appEnv.DB, {
					method: request.method,
					route: routePathFor(request.method, url.pathname),
					status: response.status,
					error_code: error.code,
				}));
				return response;
			}
			console.error(JSON.stringify({ level: "error", message: "unhandled_error" }));
			const response = errorJson(request, "internal_error", { status: 500 });
			ctx.waitUntil(recordApiDiagnostic(appEnv.DB, {
				method: request.method,
				route: routePathFor(request.method, url.pathname),
				status: response.status,
				error_code: "internal_error",
			}));
			return response;
		}
	},
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: AppEnv, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url);
	if (request.method === "GET" && url.pathname === "/health") {
		return json({ ok: true, service: "djconnect-api" });
	}

	const match = routes.find((candidate) => candidate.method === request.method && candidate.path === url.pathname);
	if (match) {
		return match.handler(request, env, ctx, url);
	}

	throw new HttpError(404, "not_found");
}

function routePathFor(method: string, pathname: string): string {
	const match = routes.find((candidate) => candidate.method === method && candidate.path === pathname);
	if (match) return match.path;
	if (method === "GET" && pathname === "/health") return "/health";
	return "unmatched";
}

export async function tokenHashForTest(token: string): Promise<string> {
	return sha256Hex(token);
}
