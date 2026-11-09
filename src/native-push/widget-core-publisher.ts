import { readFirstKeyBody } from "./first-key-service";
import { widgetCoreAccessClientId } from "./widget-core-access";
import { need, SurfaceError } from "../surface-push/wire";

const prefix = "/v1/internal/widget-core/";
const operationFields = ["install_credential_id", "operation_id", "pairing_generation", "pair_binding",
	"owner_binding", "device_binding", "core_key_thumbprint", "request_expires_at_ms", "consent_revision"] as const;
const identifier = /^[A-Za-z0-9_-]{1,128}$/;
const coordinate = /^[!-~]{1,128}$/;
const hash = /^[a-f0-9]{64}$/;
const valid = (value: unknown, pattern: RegExp) => typeof value === "string" && pattern.test(value);
const positive = (value: unknown) => typeof value === "number" && Number.isSafeInteger(value) && value > 0;

function reply(body: unknown, status: number) {
	return Response.json(body, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

/** Server-only source candidate. The authenticated publisher resolves the configured ordinary Core client. */
export function createWidgetCorePublisher(db?: D1Database, origin?: string,
	authorizePublisher?: (request: Request) => Promise<{
		clientId: string; current: () => boolean; expiresAt: number;
	} | null>) {
	return async (request: Request): Promise<Response> => {
		try {
			const path = new URL(request.url).pathname;
			const action = path.slice(prefix.length);
			need(request.method === "POST" && path === prefix + action &&
				(action === "bind" || action === "operation" || action === "withdraw"), "widget_publisher_not_found", 404);
			need(db && origin && authorizePublisher, "widget_publisher_unavailable", 503);
			const selected = new URL(origin);
			need(selected.origin === origin && selected.protocol === "https:" && !selected.port &&
				selected.hostname.includes(".") && selected.hostname !== "api.djconnect.dev", "widget_publisher_unavailable", 503);
			need(request.url === origin + path, "widget_publisher_not_found", 404);
			need(!request.headers.has("authorization"), "widget_publisher_authority_required", 403);
			const access = await authorizePublisher(request);
			need(access && widgetCoreAccessClientId.test(access.clientId) && access.current(), "widget_publisher_authority_required", 403);
			const { clientId, expiresAt } = access;
			const parsed = await readFirstKeyBody(request, 4096, true);
			need(parsed && typeof parsed === "object" && !Array.isArray(parsed));
			const body = parsed as Record<string, unknown>;
			const keys = action === "bind" ? ["ha_install_id", "device_id"] :
				action === "operation" ? operationFields : ["pair_binding", "consent_revision"];
			need(body.contract_version === 1 && Object.keys(body).length === keys.length + 1 &&
				keys.every(key => Object.hasOwn(body, key)));
			need(access.current(), "widget_publisher_authority_required", 403);

			let result: unknown;
			if (action === "bind") {
				need(valid(body.ha_install_id, coordinate) && valid(body.device_id, coordinate));
				result = await db.prepare(`INSERT INTO widget_core_machines
					(access_client_id, scope_id, ha_install_id, device_id, enabled)
					SELECT ?, ?, ?, ?, 1 WHERE ? > CAST(unixepoch('subsec') * 1000 AS INTEGER)
					ON CONFLICT(access_client_id) DO UPDATE SET enabled = 1
					WHERE enabled = 1 AND ha_install_id = excluded.ha_install_id AND device_id = excluded.device_id
					RETURNING scope_id`).bind(clientId, crypto.randomUUID(), body.ha_install_id, body.device_id, expiresAt).first();
			} else if (action === "operation") {
				need([body.install_credential_id, body.operation_id, body.pairing_generation].every(value => valid(value, identifier)) &&
					[body.pair_binding, body.owner_binding, body.device_binding, body.core_key_thumbprint].every(value => valid(value, hash)) &&
					positive(body.request_expires_at_ms) && positive(body.consent_revision));
				result = await db.prepare(`INSERT INTO widget_core_pair_authority
					(scope_id, credential_id, operation_id, pairing_generation, pair_binding, owner_binding,
					 device_binding, core_key_thumbprint, retirement_request_expires_at_ms, consent_revision, current)
					SELECT m.scope_id, i.id, ?, ?, ?, ?, ?, ?, ?, ?, 1 FROM widget_core_machines m
					JOIN install_tokens i ON i.ha_install_id = m.ha_install_id AND i.label = 'widget-install/1:' || m.scope_id
					WHERE m.access_client_id = ? AND m.enabled = 1 AND i.id = ? AND i.disabled = 0
					AND MIN(?, ?) > CAST(unixepoch('subsec') * 1000 AS INTEGER)
					AND NOT EXISTS (SELECT 1 FROM widget_core_consent_withdrawals w
						WHERE w.scope_id = m.scope_id AND w.pair_binding = ? AND w.through_revision >= ?)
					AND NOT EXISTS (SELECT 1 FROM widget_first_key_retirements WHERE pair_binding = ?)
					ON CONFLICT(scope_id, credential_id, operation_id) DO UPDATE SET current = 1
					WHERE current = 1 AND pairing_generation = excluded.pairing_generation
					AND pair_binding = excluded.pair_binding AND owner_binding = excluded.owner_binding
					AND device_binding = excluded.device_binding AND core_key_thumbprint = excluded.core_key_thumbprint
					AND retirement_request_expires_at_ms = excluded.retirement_request_expires_at_ms
					AND consent_revision = excluded.consent_revision
					RETURNING operation_id`).bind(body.operation_id, body.pairing_generation, body.pair_binding,
					body.owner_binding, body.device_binding, body.core_key_thumbprint, body.request_expires_at_ms,
					body.consent_revision, clientId, body.install_credential_id, body.request_expires_at_ms, expiresAt,
					body.pair_binding, body.consent_revision, body.pair_binding).first();
			} else {
				need(valid(body.pair_binding, hash) && positive(body.consent_revision));
				result = await db.prepare(`INSERT INTO widget_core_consent_withdrawals (scope_id, pair_binding, through_revision)
					SELECT scope_id, ?, ? FROM widget_core_machines WHERE access_client_id = ? AND enabled = 1
					AND ? > CAST(unixepoch('subsec') * 1000 AS INTEGER)
					ON CONFLICT(scope_id, pair_binding) DO UPDATE SET
					through_revision = MAX(through_revision, excluded.through_revision)
					RETURNING through_revision`).bind(body.pair_binding, body.consent_revision, clientId, expiresAt).first();
			}
			need(result, "widget_publisher_conflict", 409);
			return reply({ ok: true }, 200);
		} catch (error) {
			return error instanceof SurfaceError ? reply({ error: error.code }, error.status)
				: reply({ error: "widget_publisher_unavailable" }, 503);
		}
	};
}
