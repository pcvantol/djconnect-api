import { sha256Hex } from "../crypto";
import { HttpError } from "../http";
import { consumeBootstrapProof, issueBootstrapProof } from "../repositories/bootstrapProofs";
import { issueInstallToken } from "../repositories/installTokens";
import { enforceBootstrapRateLimit } from "../repositories/rateLimits";
import { need, SurfaceError } from "../surface-push/wire";
import { readFirstKeyBody } from "./first-key-service";

const bootstrapPath = "/v1/install/bootstrap-proof";
const exchangePath = "/v1/install/token";
const coordinateFields = ["ha_install_id", "device_id", "client_type", "integration", "integration_version"] as const;
const denied = "widget_install_authority_required";

interface InstallCoordinates {
	ha_install_id: string;
	device_id: string;
	client_type: "ios";
	integration: "djconnect_hacs";
	integration_version: string;
}

type InstallAuthority = (request: Request, input: Readonly<InstallCoordinates>) => Promise<{
	/** Opaque server-managed identity and generation for this exact installation and device. */
	scopeId: string;
	isCurrent(): boolean;
} | null>;

function reply(body: unknown, status = 200) {
	return Response.json(body, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

/** Unmounted private issuer. The ingress must verify Access and resolve the exact installation mapping. */
export function createWidgetInstallIssuer(db: D1Database, origin: string, authorize: InstallAuthority) {
	return async (request: Request): Promise<Response> => {
		try {
			const path = new URL(request.url).pathname;
			need(request.method === "POST" && (path === bootstrapPath || path === exchangePath) &&
				request.url === origin + path, "widget_install_not_found", 404);
			const exchange = path === exchangePath;
			const input = await readFirstKeyBody(request, 4096, true);
			need(input && typeof input === "object" && !Array.isArray(input));
			const value = input as Record<string, unknown>;
			const keys = exchange ? [...coordinateFields, "bootstrap_proof"] : coordinateFields;
			need(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
			need(value.client_type === "ios" && value.integration === "djconnect_hacs" &&
				([value.ha_install_id, value.device_id, value.integration_version]).every(field =>
					typeof field === "string" && /^[!-~]{1,128}$/.test(field)));
			const coordinates = Object.freeze({
				ha_install_id: value.ha_install_id as string,
				device_id: value.device_id as string,
				client_type: value.client_type,
				integration: value.integration,
				integration_version: value.integration_version as string,
			});
			const authority = await authorize(request, coordinates);
			need(authority && /^[A-Za-z0-9_-]{1,128}$/.test(authority.scopeId), denied, 403);
			const proofScope = "widget-install/1:" + authority.scopeId;
			const check = () => need(!request.signal.aborted && authority.isCurrent() === true, denied, 403);
			check();
			await enforceBootstrapRateLimit(db, { ip: "widget-install:" + authority.scopeId, ...coordinates });
			check();
			if (!exchange) {
				const result = await issueBootstrapProof(db, { ...coordinates, pairing_session_id: proofScope, ttl_seconds: 60 });
				check();
				return reply({ ok: true, bootstrap_proof: result.proof, expires_at: result.expiresAt });
			}
			const proof = value.bootstrap_proof;
			need(typeof proof === "string" && /^djcboot_[A-Za-z0-9_-]{1,256}$/.test(proof));
			const scoped = await db.prepare("SELECT 1 FROM bootstrap_proofs WHERE proof_hash = ? AND pairing_session_id = ?")
				.bind(await sha256Hex(proof), proofScope).first();
			need(scoped, denied, 403);
			check();
			await consumeBootstrapProof(db, { ...coordinates, bootstrap_proof: proof });
			check();
			const token = await issueInstallToken(db, coordinates);
			check();
			return reply({ ok: true, success: true, id: token.id, token: token.token, install_token: token.token,
				token_hash: token.tokenHash, expires_at: null });
		} catch (error) {
			if (error instanceof SurfaceError || error instanceof HttpError) return reply({ error: error.code }, error.status);
			return reply({ error: "widget_install_unavailable" }, 503);
		}
	};
}
