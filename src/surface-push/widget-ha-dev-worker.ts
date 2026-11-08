import { WorkerEntrypoint } from "cloudflare:workers";
import { createWidgetFirstKeyHandler, isWidgetFirstKeyRoute, type WidgetFirstKeyPolicy } from "../native-push/first-key-service";
import type { AppEnv } from "../types";
import { createSurfaceEnrollment } from "./enrollment";
import { ENROLLMENT_PREFIX } from "./enrollment-wire";
import { createPrivateWidgetIngress } from "./private-widget-ingress";

interface WidgetPilotBindings {
	WIDGET_WORKER_VERSION?: WorkerVersionMetadata;
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

function composePilot(bindings: WidgetPilotBindings, version: string) {
	const { WIDGET_PILOT_ORIGIN: origin, WIDGET_ACCESS_ISSUER: issuer, WIDGET_ACCESS_AUDIENCE: audience,
		WIDGET_ACCESS_CLIENT_ID: clientId, WIDGET_ACCESS_GENERATION: generation,
		WIDGET_PILOT_EXPIRES_AT_MS: expiration, WIDGET_HA_DEV_DB: db,
		WIDGET_TOKEN_ENCRYPTION_KEY: encryptionKey, WIDGET_ENROLLMENT_OPERATOR_SECRET: operator } = bindings;
	const credentialGeneration = Number(generation), expiresAt = Number(expiration);
	if (!origin || !issuer || !audience || !clientId || !db || !encryptionKey ||
		!Number.isSafeInteger(credentialGeneration) || credentialGeneration < 1 ||
		String(credentialGeneration) !== generation || !Number.isSafeInteger(expiresAt) ||
		String(expiresAt) !== expiration) return null;

	const matches = (candidate: WidgetPilotBindings) =>
		candidate.WIDGET_WORKER_VERSION?.id === version && candidate.WIDGET_PILOT_MODE === "transport-v1" &&
		candidate.WIDGET_PILOT_EXPIRES_AT_MS === expiration && candidate.WIDGET_ACCESS_GENERATION === generation &&
		candidate.WIDGET_PILOT_ORIGIN === origin && candidate.WIDGET_ACCESS_ISSUER === issuer &&
		candidate.WIDGET_ACCESS_AUDIENCE === audience && candidate.WIDGET_ACCESS_CLIENT_ID === clientId &&
		candidate.WIDGET_HA_DEV_DB === db && candidate.WIDGET_TOKEN_ENCRYPTION_KEY === encryptionKey &&
		candidate.WIDGET_ENROLLMENT_OPERATOR_SECRET === operator;
	let retired = false;
	const current = (candidate = bindings) => {
		retired ||= Date.now() >= expiresAt || !matches(bindings) || !matches(candidate);
		return !retired;
	};
	if (!current()) return null;

	// Both entrypoints use this captured database, with no provider bindings.
	const env = Object.freeze({ DB: db, APNS_TOKEN_ENCRYPTION_KEY: encryptionKey,
		DJCONNECT_RELAY_SECRET: operator }) as AppEnv;
	const ingress = createPrivateWidgetIngress({
		env, origin, issuer, audience, clientId, credentialGeneration, maxAssertionAgeSeconds: 30,
		isCredentialCurrent: generation => generation === credentialGeneration && current(),
		fetcher: async () => { throw new Error("Provider egress disabled in WidgetKit transport pilot"); },
	});
	const enrollment = operator ? createSurfaceEnrollment({ env, isCurrent: () => current() }) : null;
	return { current, ingress, enrollment };
}

// Worker versions pin bindings across isolates. This latch additionally retires
// an observed mismatch for the remainder of this version's life in an isolate.
const pilots = new Map<string, ReturnType<typeof composePilot>>();

function transportPilot(bindings: WidgetPilotBindings) {
	const version = bindings.WIDGET_WORKER_VERSION?.id;
	if (!version) return null;
	if (!pilots.has(version)) {
		try {
			pilots.set(version, composePilot(bindings, version));
		} catch {
			pilots.set(version, null);
		}
	}
	const pilot = pilots.get(version);
	return pilot?.current(bindings) ? pilot : null;
}

/** Named service binding. The public fetch entrypoint never forwards operator requests. */
export class WidgetEnrollmentOperator extends WorkerEntrypoint<WidgetPilotBindings> {
	async fetch(request: Request): Promise<Response> {
		const path = new URL(request.url).pathname;
		if ((path !== authorize && path !== revoke) || request.url !== operatorOrigin + path ||
			request.method !== "POST") return closed(404);
		const pilot = transportPilot(this.env);
		if (!pilot?.enrollment) return closed(503);
		return pilot.enrollment(
			new Request("https://api.djconnect.dev" + path, request));
	}
}

export function createWidgetHaDevWorker(firstKeyPolicy?: WidgetFirstKeyPolicy) {
	return {
		async fetch(request: Request, env: WidgetPilotBindings, ctx: ExecutionContext): Promise<Response> {
			const { pathname } = new URL(request.url);
			if (pathname === relayEvent) return closed(404);
			const pilot = transportPilot(env);
			if (!pilot) return closed(503);
			if (isWidgetFirstKeyRoute(pathname)) {
				return createWidgetFirstKeyHandler(env.WIDGET_HA_DEV_DB!, env.WIDGET_PILOT_ORIGIN!,
					() => pilot.current(env), firstKeyPolicy)(request);
			}
			return pilot.ingress(request, ctx);
		},
	} satisfies ExportedHandler<WidgetPilotBindings>;
}

export default createWidgetHaDevWorker();
