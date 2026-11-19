import { createWatchAccessKeyResolver } from "../watch-lifecycle/access-jwks";
import { createWidgetFirstKeyAppleVerifier } from "./first-key-apple";
import { createWidgetFirstKeyHandler, createWidgetFirstKeyRetirementHandler, isWidgetFirstKeyRoute } from "./first-key-service";
import type { FirstKeyPairBinding } from "./first-key-wire";
import { createWidgetInstallIssuer } from "./widget-install-issuer";
import { verifyWidgetCoreAccess } from "./widget-core-access";

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

function reply(status: number) {
	const error = status === 404 ? "widget_core_not_found" :
		status === 403 ? "widget_core_authority_required" : "widget_core_unavailable";
	return Response.json({ error }, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

/** Standalone HA-dev entry. Binding the D1 database alone does not enable it. */
export function createWidgetCoreHaDevWorker(resolveKeys?: Parameters<typeof verifyWidgetCoreAccess>[7]) {
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
				if ((installPaths.has(pathname) || pathname === retirementPath) && request.headers.has("authorization")) return reply(403);
				const access = await verifyWidgetCoreAccess(request, ctx, issuer, audience, clientId, expiresAt,
					() => env.WIDGET_CORE_MODE === mode && env.WIDGET_HA_DEV_DB === db &&
						env.WIDGET_CORE_ORIGIN === origin && env.WIDGET_CORE_ACCESS_ISSUER === issuer &&
						env.WIDGET_CORE_ACCESS_AUDIENCE === audience && env.WIDGET_CORE_ACCESS_CLIENT_ID === clientId &&
						env.WIDGET_CORE_POLICY_ID === policyId && env.WIDGET_CORE_EXPIRES_AT_MS === expiration &&
						env.WIDGET_CORE_APP_ID === appId && env.WIDGET_CORE_APP_BUILD === build, resolveKeys);
				if (!access) return reply(403);
				const { current, expiresAt: accessExpiresAt } = access;

				const machine = await db.prepare(`SELECT scope_id, ha_install_id, device_id
					FROM widget_core_machines WHERE access_client_id = ? AND enabled = 1`).bind(clientId).first<Machine>();
				if (!machine || !identifier.test(machine.scope_id) || !current()) return reply(403);
				const machineCurrent = async () => current() && !!await db.prepare(`SELECT 1 FROM widget_core_machines
					WHERE access_client_id = ? AND scope_id = ? AND ha_install_id = ? AND device_id = ? AND enabled = 1`)
					.bind(clientId, machine.scope_id, machine.ha_install_id, machine.device_id).first() && current();

				const pairQuery = (credentialId: string, pair: FirstKeyPairBinding & { operation_id: string },
					retirementDeadline: number | null) => {
					const lifecycle = retirementDeadline === null
						? `p.current = 1 AND i.disabled = 0 AND i.label = 'widget-install/1:' || m.scope_id
							AND NOT EXISTS (SELECT 1 FROM widget_core_consent_withdrawals w
								WHERE w.scope_id = p.scope_id AND w.pair_binding = p.pair_binding
								AND w.through_revision >= p.consent_revision)`
						: "p.retirement_request_expires_at_ms = ?";
					return { sql: `SELECT 1 FROM widget_core_pair_authority p
						JOIN widget_core_machines m ON m.scope_id = p.scope_id AND m.enabled = 1
						JOIN install_tokens i ON i.id = p.credential_id AND i.ha_install_id = m.ha_install_id
						WHERE m.access_client_id = ? AND m.scope_id = ? AND m.ha_install_id = ? AND m.device_id = ? AND p.credential_id = ?
						AND p.operation_id = ? AND p.pairing_generation = ? AND p.pair_binding = ?
						AND p.owner_binding = ? AND p.device_binding = ? AND p.core_key_thumbprint = ? AND ${lifecycle}`,
						values: [clientId, machine.scope_id, machine.ha_install_id, machine.device_id, credentialId, pair.operation_id,
							pair.pairing_generation, pair.pair_binding, pair.owner_binding, pair.device_binding,
							pair.core_key_thumbprint, ...(retirementDeadline === null ? [] : [retirementDeadline])] };
				};
				const allowedPair = async (credentialId: string, pair: FirstKeyPairBinding & { operation_id: string }) => {
					const query = pairQuery(credentialId, pair, null);
					const result = await db.prepare(query.sql).bind(...query.values).first();
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
					return await createWidgetFirstKeyRetirementHandler(db, origin, event => {
						if (!current()) return null;
						const query = pairQuery(event.install_credential_id, event, event.request_expires_at_ms);
						return {
							sql: `EXISTS (${query.sql}) AND ? > CAST(unixepoch('subsec') * 1000 AS INTEGER)`,
							values: [...query.values, accessExpiresAt],
						};
					})(request);
				}
				return await createWidgetFirstKeyHandler(db, origin, current, {
					id: policyId, expiresAt, isCurrent: current, isPairCurrent: allowedPair,
					pairSqlGuard: (credentialId, pair) => {
						const query = pairQuery(credentialId, pair, null);
						return { sql: `EXISTS (${query.sql})`, values: query.values };
					},
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
