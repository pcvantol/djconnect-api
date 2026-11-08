import { base64Url } from "../crypto";
import { parseStrictJson } from "../surface-push/wire";
import { createWatchAccessKeyResolver } from "../watch-lifecycle/access-jwks";
import { createWidgetFirstKeyAppleVerifier } from "./first-key-apple";
import { createWidgetFirstKeyHandler, createWidgetFirstKeyRetirementHandler, isWidgetFirstKeyRoute } from "./first-key-service";
import type { FirstKeyPairBinding } from "./first-key-wire";
import { createWidgetInstallIssuer } from "./widget-install-issuer";

interface Bindings {
	WIDGET_CORE_MODE?: string;
	WIDGET_CORE_ORIGIN?: string;
	WIDGET_CORE_ACCESS_ISSUER?: string;
	WIDGET_CORE_ACCESS_AUDIENCE?: string;
	WIDGET_CORE_ACCESS_CLIENT_ID?: string;
	WIDGET_CORE_POLICY_ID?: string;
	WIDGET_CORE_EXPIRES_AT_MS?: string;
	WIDGET_CORE_APP_ID?: string;
	WIDGET_CORE_APP_BUILD?: string;
	WIDGET_HA_DEV_DB?: D1Database;
}

interface Machine {
	scope_id: string;
	ha_install_id: string;
	device_id: string;
}

const installPaths = new Set(["/v1/install/bootstrap-proof", "/v1/install/token"]);
const retirementPath = "/v1/push/native/key/retire";
const identifier = /^[A-Za-z0-9_-]{1,128}$/;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function reply(status: number) {
	const error = status === 404 ? "widget_core_not_found" :
		status === 403 ? "widget_core_authority_required" : "widget_core_unavailable";
	return Response.json({ error }, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

function decodeSegment(value: string): Uint8Array<ArrayBuffer> {
	if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError("invalid Access segment");
	const decoded = Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), char => char.charCodeAt(0));
	if (base64Url(decoded.buffer) !== value) throw new TypeError("noncanonical Access segment");
	return decoded;
}

function claims(value: string): Record<string, unknown> {
	const parsed = parseStrictJson(decoder.decode(decodeSegment(value)));
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("invalid Access claims");
	return parsed as Record<string, unknown>;
}

/** Standalone HA-dev entry. Binding the D1 database alone does not enable it. */
export function createWidgetCoreHaDevWorker(resolveKeys = createWatchAccessKeyResolver) {
	return {
		async fetch(request: Request, env: Bindings, ctx: ExecutionContext): Promise<Response> {
			const { pathname } = new URL(request.url);
			if (!installPaths.has(pathname) && pathname !== retirementPath && !isWidgetFirstKeyRoute(pathname)) return reply(404);
			const { WIDGET_CORE_MODE: mode, WIDGET_CORE_ORIGIN: origin, WIDGET_CORE_ACCESS_ISSUER: issuer,
				WIDGET_CORE_ACCESS_AUDIENCE: audience, WIDGET_CORE_ACCESS_CLIENT_ID: clientId,
				WIDGET_CORE_POLICY_ID: policyId, WIDGET_CORE_EXPIRES_AT_MS: expiration,
				WIDGET_CORE_APP_ID: appId, WIDGET_CORE_APP_BUILD: build, WIDGET_HA_DEV_DB: db } = env;
			const expiresAt = Number(expiration);
			if (mode !== "first-key-v1" || !origin || !issuer || !audience || !clientId || !policyId ||
				!identifier.test(policyId) || !appId || !/^[A-Z0-9]{10}\.[A-Za-z0-9.-]{1,150}$/.test(appId) ||
				!build || !/^[0-9]{1,16}$/.test(build) || !db || !Number.isSafeInteger(expiresAt) ||
				String(expiresAt) !== expiration || Date.now() >= expiresAt) return reply(503);
			try {
				const selectedOrigin = new URL(origin);
				if (selectedOrigin.origin !== origin || selectedOrigin.protocol !== "https:" || selectedOrigin.port ||
					selectedOrigin.hostname === "api.djconnect.dev" || !selectedOrigin.hostname.includes(".")) return reply(503);
				if (request.method !== "POST" || request.url !== origin + pathname) return reply(404);
				if (!ctx.access || request.headers.has("cookie") || request.headers.has("origin") ||
					request.headers.has("content-encoding")) return reply(403);
				if ((installPaths.has(pathname) || pathname === retirementPath) && request.headers.has("authorization")) return reply(403);
				const token = request.headers.get("cf-access-jwt-assertion");
				if (!token || token.length > 8192) return reply(403);
				const parts = token.split(".");
				if (parts.length !== 3) return reply(403);
				const [header, payload, signature] = parts;
				const { alg, kid, crit } = claims(header);
				const { iss, aud, common_name, type, sub, exp, iat } = claims(payload);
				if (alg !== "RS256" || crit !== undefined || typeof kid !== "string" || !identifier.test(kid) ||
					iss !== issuer || !Array.isArray(aud) || aud.length !== 1 || aud[0] !== audience ||
					common_name !== clientId || type !== "app" || sub !== "" ||
					typeof exp !== "number" || typeof iat !== "number" || !Number.isSafeInteger(exp) ||
					!Number.isSafeInteger(iat)) return reply(403);
				const requestExpiry = Math.min(expiresAt, exp * 1000, (iat + 30) * 1000);
				const current = () => !request.signal.aborted && iat <= Math.floor(Date.now() / 1000) &&
					Date.now() < requestExpiry && env.WIDGET_CORE_MODE === mode && env.WIDGET_HA_DEV_DB === db &&
					env.WIDGET_CORE_ORIGIN === origin && env.WIDGET_CORE_ACCESS_ISSUER === issuer &&
					env.WIDGET_CORE_ACCESS_AUDIENCE === audience && env.WIDGET_CORE_ACCESS_CLIENT_ID === clientId &&
					env.WIDGET_CORE_POLICY_ID === policyId && env.WIDGET_CORE_EXPIRES_AT_MS === expiration &&
					env.WIDGET_CORE_APP_ID === appId && env.WIDGET_CORE_APP_BUILD === build;
				if (!current()) return reply(403);
				const key = await resolveKeys(issuer)(kid, AbortSignal.any([request.signal, AbortSignal.timeout(3000)]));
				if (!key || key.type !== "public" ||
					(key.algorithm as { hash?: { name: string } }).hash?.name !== "SHA-256" ||
					!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeSegment(signature),
						Uint8Array.from(new TextEncoder().encode(header + "." + payload))) || !current()) return reply(403);

				const machine = await db.prepare(`SELECT scope_id, ha_install_id, device_id
					FROM widget_core_machines WHERE access_client_id = ? AND enabled = 1`).bind(clientId).first<Machine>();
				if (!machine || !identifier.test(machine.scope_id) || !current()) return reply(403);
				const machineCurrent = async () => current() && !!await db.prepare(`SELECT 1 FROM widget_core_machines
					WHERE access_client_id = ? AND scope_id = ? AND ha_install_id = ? AND device_id = ? AND enabled = 1`)
					.bind(clientId, machine.scope_id, machine.ha_install_id, machine.device_id).first() && current();

				const allowedPair = async (credentialId: string, pair: FirstKeyPairBinding & { operation_id: string },
					retirementDeadline: number | null = null) => {
					const lifecycle = retirementDeadline === null
						? "p.current = 1 AND i.disabled = 0 AND i.label = 'widget-install/1:' || m.scope_id"
						: "p.retirement_request_expires_at_ms = ?";
					const result = await db.prepare(`SELECT 1 FROM widget_core_pair_authority p
						JOIN widget_core_machines m ON m.scope_id = p.scope_id AND m.enabled = 1
						JOIN install_tokens i ON i.id = p.credential_id AND i.ha_install_id = m.ha_install_id
						WHERE m.access_client_id = ? AND m.scope_id = ? AND m.device_id = ? AND p.credential_id = ?
						AND p.operation_id = ? AND p.pairing_generation = ? AND p.pair_binding = ?
						AND p.owner_binding = ? AND p.device_binding = ? AND p.core_key_thumbprint = ? AND ${lifecycle}`)
						.bind(clientId, machine.scope_id, machine.device_id, credentialId, pair.operation_id,
							pair.pairing_generation, pair.pair_binding, pair.owner_binding, pair.device_binding,
							pair.core_key_thumbprint, ...(retirementDeadline === null ? [] : [retirementDeadline])).first();
					return !!result && current();
				};
				if (installPaths.has(pathname)) {
					return await createWidgetInstallIssuer(db, origin, async (_request, input) => {
						if (input.ha_install_id !== machine.ha_install_id || input.device_id !== machine.device_id ||
							!await machineCurrent()) return null;
						return { scopeId: machine.scope_id, isCurrent: machineCurrent };
					})(request);
				}
				if (pathname === retirementPath) {
					return await createWidgetFirstKeyRetirementHandler(db, origin, async (_request, event) =>
						allowedPair(event.install_credential_id, event, event.request_expires_at_ms))(request);
				}
				return await createWidgetFirstKeyHandler(db, origin, current, {
					id: policyId, expiresAt, isCurrent: current, isPairCurrent: allowedPair,
					verifyApple: createWidgetFirstKeyAppleVerifier({
						profile: "host_wake_apple_properties_attestation_v2", app_identifier: appId,
						app_attest_environment: "development", bundle_version: build, launch_validation_category_b64: "AwAAAA==",
					}),
				}, async () => machineCurrent())(request);
			} catch {
				return reply(503);
			}
		},
	} satisfies ExportedHandler<Bindings>;
}

export default createWidgetCoreHaDevWorker();
