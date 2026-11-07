import { WorkerEntrypoint } from "cloudflare:workers";
import type { AppEnv } from "../types";
import { createSurfaceEnrollment } from "./enrollment";
import { ENROLLMENT_PREFIX } from "./enrollment-wire";
import { createPrivateWidgetIngress } from "./private-widget-ingress";

interface WidgetPilotBindings {
	WIDGET_PILOT_MODE?: string;
	WIDGET_PILOT_ORIGIN?: string;
	WIDGET_ACCESS_ISSUER?: string;
	WIDGET_ACCESS_AUDIENCE?: string;
	WIDGET_ACCESS_CLIENT_ID?: string;
	WIDGET_ACCESS_GENERATION?: string;
	WIDGET_PILOT_EXPIRES_AT_MS?: string;
	WIDGET_HA_DEV_DB?: D1Database;
	WIDGET_TOKEN_ENCRYPTION_KEY?: string;
	WIDGET_ENROLLMENT_OPERATOR_SECRET?: string;
}

const relayEvent = "/v1/push/surface/event";
const authorize = ENROLLMENT_PREFIX + "operator/authorize";
const revoke = ENROLLMENT_PREFIX + "operator/revoke";
const operatorOrigin = "https://widget-enrollment.internal";

function closed(status: 404 | 503) {
	return Response.json({ contract_version: 1, success: false,
		error: status === 404 ? "surface_route_not_found" : "surface_service_unavailable" },
	{ status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

function transportPilot(bindings: WidgetPilotBindings) {
	const { WIDGET_PILOT_ORIGIN: origin, WIDGET_ACCESS_ISSUER: issuer, WIDGET_ACCESS_AUDIENCE: audience,
		WIDGET_ACCESS_CLIENT_ID: clientId, WIDGET_ACCESS_GENERATION: generation,
		WIDGET_PILOT_EXPIRES_AT_MS: expiration, WIDGET_HA_DEV_DB: db,
		WIDGET_TOKEN_ENCRYPTION_KEY: encryptionKey, WIDGET_ENROLLMENT_OPERATOR_SECRET: operator } = bindings;
	const credentialGeneration = Number(generation), expiresAt = Number(expiration);
	if (!origin || !issuer || !audience || !clientId || !db || !encryptionKey ||
		!Number.isSafeInteger(credentialGeneration) || credentialGeneration < 1 ||
		String(credentialGeneration) !== generation || !Number.isSafeInteger(expiresAt) ||
		String(expiresAt) !== expiration) return null;

	const current = () => bindings.WIDGET_PILOT_MODE === "transport-v1" && Date.now() < expiresAt &&
		bindings.WIDGET_PILOT_EXPIRES_AT_MS === expiration && bindings.WIDGET_ACCESS_GENERATION === generation &&
		bindings.WIDGET_PILOT_ORIGIN === origin && bindings.WIDGET_ACCESS_ISSUER === issuer &&
		bindings.WIDGET_ACCESS_AUDIENCE === audience && bindings.WIDGET_ACCESS_CLIENT_ID === clientId &&
		bindings.WIDGET_HA_DEV_DB === db && bindings.WIDGET_TOKEN_ENCRYPTION_KEY === encryptionKey &&
		bindings.WIDGET_ENROLLMENT_OPERATOR_SECRET === operator;
	if (!current()) return null;

	// The pilot accepts only dedicated bindings. Provider configuration is absent.
	const env = Object.freeze({ DB: db, APNS_TOKEN_ENCRYPTION_KEY: encryptionKey,
		DJCONNECT_RELAY_SECRET: operator }) as AppEnv;
	return { env, origin, issuer, audience, clientId, credentialGeneration, current, operator };
}

/** Named service binding. The public fetch entrypoint never forwards operator requests. */
export class WidgetEnrollmentOperator extends WorkerEntrypoint<WidgetPilotBindings> {
	async fetch(request: Request): Promise<Response> {
		const path = new URL(request.url).pathname;
		if ((path !== authorize && path !== revoke) || request.url !== operatorOrigin + path ||
			request.method !== "POST") return closed(404);
		const pilot = transportPilot(this.env);
		if (!pilot?.operator) return closed(503);
		return createSurfaceEnrollment({ env: pilot.env, isCurrent: pilot.current })(
			new Request("https://api.djconnect.dev" + path, request));
	}
}

export default {
	async fetch(request: Request, env: WidgetPilotBindings, ctx: ExecutionContext): Promise<Response> {
		if (new URL(request.url).pathname === relayEvent) return closed(404);
		const pilot = transportPilot(env);
		if (!pilot) return closed(503);
		try {
			const ingress = createPrivateWidgetIngress({
				env: pilot.env, origin: pilot.origin, issuer: pilot.issuer, audience: pilot.audience,
				clientId: pilot.clientId, credentialGeneration: pilot.credentialGeneration,
				maxAssertionAgeSeconds: 30,
				isCredentialCurrent: generation => generation === pilot.credentialGeneration && pilot.current(),
				fetcher: async () => { throw new Error("Provider egress disabled in WidgetKit transport pilot"); },
			});
			return await ingress(request, ctx);
		} catch {
			return closed(503);
		}
	},
} satisfies ExportedHandler<WidgetPilotBindings>;
