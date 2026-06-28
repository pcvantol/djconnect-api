import { requireAdminAuth } from "../auth";
import { json, readJson } from "../http";
import { listAdminRegistrations, revokeInstallToken } from "../repository";
import type { AppEnv, RevokeInstallTokenRequest } from "../types";
import { validateAdminRegistrationsQuery, validateRevokeInstallToken } from "../validation";

export async function listRegistrations(request: Request, env: AppEnv, url: URL): Promise<Response> {
	await requireAdminAuth(request, env);
	const result = await listAdminRegistrations(env.DB, validateAdminRegistrationsQuery(url));
	return json({ ok: true, ...result });
}

export async function revokeToken(request: Request, env: AppEnv): Promise<Response> {
	await requireAdminAuth(request, env);
	const input = await readJson<RevokeInstallTokenRequest>(request);
	validateRevokeInstallToken(input);
	const result = await revokeInstallToken(env.DB, input);
	return json({ ok: true, revoked: result.revoked });
}
