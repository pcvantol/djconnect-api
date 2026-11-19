import { boundedWork, createMomentTransport, type MomentPorts } from "./service";
import { MomentError, VERSION, need, readEnvelope, type MomentEvent } from "./wire";

export type HttpAction = "send" | "status" | "cancel";
/** Server-supplied verifier creates ports bound to this authenticated request.
 * Raw bounded bytes are preserved for an actual selected signature scheme.
 * This module provides no verifier implementation, credential or public URI. */
export type AuthenticatedPorts = (request: Request, event: Readonly<MomentEvent>, action: HttpAction,
	body: Uint8Array, signal: AbortSignal) => Promise<MomentPorts>;

const headers = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store",
	"referrer-policy": "no-referrer", "x-content-type-options": "nosniff" };
const json = (body: unknown, status: number, extra: Record<string, string> = {}) =>
	new Response(JSON.stringify(body), { status, headers: { ...headers, ...extra } });

export function createMomentHttpHandler(authenticate: AuthenticatedPorts) {
	need(typeof authenticate === "function", "moment_configuration", 503);
	return async (request: Request, action: HttpAction): Promise<Response> => {
		let service: ReturnType<typeof createMomentTransport> | undefined;
		try {
			need(["send", "status", "cancel"].includes(action), "moment_action");
			if (request.method !== "POST") return json({ version: VERSION, error: "moment_method" }, 405, { allow: "POST" });
			const { event, bytes } = await readEnvelope(request);
			const signal = AbortSignal.any([request.signal, AbortSignal.timeout(25_000)]);
			const authSignal = AbortSignal.any([signal, AbortSignal.timeout(5000)]);
			const ports = await boundedWork(authenticate(request, event, action, bytes, authSignal), authSignal);
			need(!signal.aborted, "moment_cancelled", 408);
			service = createMomentTransport(ports);
			const result = action === "send" ? await service.dispatch(event, signal)
				: action === "cancel" ? await service.cancel(event, signal) : await service.status(event, signal);
			if (!result) return json({ version: VERSION, error: "moment_operation_missing" }, 404);
			const status = result.state === "capacity" ? 503 : ["unknown", "retryable"].includes(result.state) ? 202 : 200;
			const retry: Record<string, string> = {};
			if (result.retry_at_ms !== null) {
				const now = ports.now();
				if (Number.isSafeInteger(now)) retry["retry-after"] = String(Math.max(1, Math.ceil((result.retry_at_ms - now) / 1000)));
			}
			return json({ version: VERSION, event_id: result.event_id, state: result.state,
				provider_status: result.provider_status, transport_expires_at_ms: result.expires_at_ms,
				retry_at_ms: result.retry_at_ms }, status, retry);
		} catch (error) {
			// Never echo private supplier/provider messages, body text, headers or tokens.
			return error instanceof MomentError
				? json({ version: VERSION, error: error.code }, error.status)
				: json({ version: VERSION, error: "moment_unavailable" }, 503);
		} finally { service?.close(); }
	};
}
