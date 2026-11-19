import { requireInstallAuth } from "../auth";
import { json, readJson } from "../http";
import { unregister, upsertRegistration } from "../repository";
import { deliverPushEvent } from "../services/pushDelivery";
import type { AppEnv, PushEventRequest, RegisterRequest, UnregisterRequest } from "../types";
import { requireBearerHeader, validatePushEvent, validateRegister, validateUnregister } from "../validation";

export async function registerDevice(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<RegisterRequest>(request);
	requireBearerHeader(request);
	validateRegister(input);
	await requireInstallAuth(request, env, input.ha_install_id);
	const result = await upsertRegistration(env.DB, env, input);
	return json({ ok: true, id: result.id, apns_token_hash: result.tokenHash });
}

export async function unregisterDevice(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<UnregisterRequest>(request);
	requireBearerHeader(request);
	validateUnregister(input);
	await requireInstallAuth(request, env, input.ha_install_id);
	const changes = await unregister(env.DB, input);
	return json({ ok: true, disabled: changes });
}

export async function sendPushEvent(request: Request, env: AppEnv, ctx: ExecutionContext): Promise<Response> {
	const input = await readJson<PushEventRequest>(request);
	requireBearerHeader(request);
	validatePushEvent(input);
	await requireInstallAuth(request, env, input.ha_install_id);
	const result = await deliverPushEvent(env, input);
	ctx.waitUntil(result.audit);
	return json({ ok: true, matched: result.matched, delivered: result.delivered, failed: result.failed });
}
