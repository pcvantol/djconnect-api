import { sha256Hex } from "./crypto";
import { listRegistrations, revokeToken } from "./handlers/admin";
import { issueBootstrapProofHandler, issueInstallTokenHandler, rotateInstallTokenHandler } from "./handlers/install";
import { registerDevice, sendPushEvent, unregisterDevice } from "./handlers/push";
import { errorJson, HttpError, json } from "./http";
import type { AppEnv } from "./types";

type RouteHandler = (request: Request, env: AppEnv, ctx: ExecutionContext, url: URL) => Promise<Response>;

const routes: Array<{ method: string; path: string; handler: RouteHandler }> = [
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
		try {
			return await route(request, env as AppEnv, ctx);
		} catch (error) {
			if (error instanceof HttpError) {
				return errorJson(request, error.code, { status: error.status });
			}
			console.error(JSON.stringify({ level: "error", message: "unhandled_error" }));
			return errorJson(request, "internal_error", { status: 500 });
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

	return errorJson(request, "not_found", { status: 404 });
}

export async function tokenHashForTest(token: string): Promise<string> {
	return sha256Hex(token);
}
