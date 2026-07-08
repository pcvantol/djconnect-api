import { requireAdminAuth, requireInstallAuth } from "../auth";
import { json, readJson } from "../http";
import { consumeBootstrapProof, enforceBootstrapRateLimit, issueBootstrapProof, issueInstallToken, rotateInstallToken } from "../repository";
import type { AppEnv, BootstrapProofRequest, InstallTokenRequest, RotateInstallTokenRequest } from "../types";
import { requireBearerHeader, validateBootstrapProofRequest, validateInstallTokenRequest, validatePairingBootstrapProofRequest, validateRotateInstallToken } from "../validation";

export async function issueBootstrapProofHandler(request: Request, env: AppEnv): Promise<Response> {
	await requireAdminAuth(request, env);
	const input = await readJson<BootstrapProofRequest>(request);
	validateBootstrapProofRequest(input);
	const result = await issueBootstrapProof(env.DB, input);
	return json({ ok: true, id: result.id, bootstrap_proof: result.proof, proof_hash: result.proofHash, expires_at: result.expiresAt });
}

export async function issuePairingBootstrapProofHandler(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<BootstrapProofRequest>(request);
	validatePairingBootstrapProofRequest(input);
	await enforceBootstrapRateLimit(env.DB, {
		ip: clientIp(request),
		ha_install_id: input.ha_install_id!,
		device_id: input.device_id,
	});
	const result = await issueBootstrapProof(env.DB, { ...input, ttl_seconds: 300 });
	return json({ ok: true, success: true, bootstrap_proof: result.proof, expires_at: result.expiresAt });
}

export async function issueInstallTokenHandler(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<InstallTokenRequest>(request);
	validateInstallTokenRequest(input);
	await enforceBootstrapRateLimit(env.DB, {
		ip: clientIp(request),
		ha_install_id: input.ha_install_id,
		device_id: input.device_id!,
	});
	await consumeBootstrapProof(env.DB, input);
	const result = await issueInstallToken(env.DB, input);
	return json({
		ok: true,
		success: true,
		id: result.id,
		token: result.token,
		install_token: result.token,
		token_hash: result.tokenHash,
		expires_at: null,
	});
}

export async function rotateInstallTokenHandler(request: Request, env: AppEnv): Promise<Response> {
	const input = await readJson<RotateInstallTokenRequest>(request);
	requireBearerHeader(request);
	validateRotateInstallToken(input);
	await requireInstallAuth(request, env, input.ha_install_id);
	const result = await rotateInstallToken(env.DB, input);
	return json({ ok: true, id: result.id, token: result.token, token_hash: result.tokenHash });
}

function clientIp(request: Request): string {
	return request.headers.get("cf-connecting-ip")
		?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
		?? "unknown";
}
