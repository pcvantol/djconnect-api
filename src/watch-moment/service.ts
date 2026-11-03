import { sha256Hex } from "../crypto";
import type { Registration } from "../types";
import { buildMomentNotification } from "./payload";
import type { Sender } from "./relay";
import { MomentStore, type Limits, type Operation, type State } from "./store";
import { CATEGORY, canonical, decodeEvent, need, type MomentEvent } from "./wire";

export interface Admission {
	/** Original server-verified publication and exact recipient; never caller booleans. */
	event_hash: string;
	recipient_binding: string;
	registration_binding: string;
	eligible_since_ms: number;
	expires_at_ms: number;
	/** Required for send; original withdrawal needs no active native credential. */
	registration?: Registration;
}
type Action = "send" | "cancel";
export interface MomentPorts {
	db: D1Database;
	/** Actual Core/registry authorization supplier; no implementation/default is supplied here. */
	admit(event: Readonly<MomentEvent>, action: Action, signal: AbortSignal): Promise<Admission>;
	/** Synchronous final currentness/rights/generation/opt-in check, also after every await. */
	assertCurrent(admission: Readonly<Admission>, action: Action): void;
	now(): number;
	send: Sender;
	limits: Limits;
}
export interface MomentReceipt {
	event_id: string;
	state: State | "capacity";
	provider_status: number | null;
	expires_at_ms: number;
	retry_at_ms: number | null;
}
const hex = (v: unknown) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
export async function boundedWork<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
	let abort: (() => void) | undefined;
	const cancelled = new Promise<never>((_resolve, reject) => {
		abort = () => reject(new Error("moment_work_cancelled"));
		if (signal.aborted) abort(); else signal.addEventListener("abort", abort, { once: true });
	});
	try { return await Promise.race([cancelled, work]); }
	finally { if (abort) signal.removeEventListener("abort", abort); }
}

export function createMomentTransport(ports: MomentPorts) {
	need(ports && [ports.admit, ports.assertCurrent, ports.now, ports.send].every(v => typeof v === "function"), "moment_configuration", 503);
	const limits = Object.freeze({ ...ports.limits });
	need(Number.isSafeInteger(limits.capacity) && limits.capacity >= 2 && limits.capacity <= 4096, "moment_configuration", 503);
	need(Number.isSafeInteger(limits.installationCapacity) && limits.installationCapacity >= 2 && limits.installationCapacity <= limits.capacity, "moment_configuration", 503);
	need(Number.isSafeInteger(limits.recipientBurst) && limits.recipientBurst >= 1 && limits.recipientBurst <= 10, "moment_configuration", 503);
	ports = Object.freeze({ ...ports, limits });
	const store = new MomentStore(ports.db);
	let closed = false;
	async function prepare(value: unknown, action: Action, signal: AbortSignal) {
		const event = decodeEvent(value);
		need(signal instanceof AbortSignal && !signal.aborted && !closed, "moment_cancelled", 409);
		const requestHash = await sha256Hex(canonical(event));
		need(!signal.aborted && !closed, "moment_cancelled", 409);
		const admissionSignal = AbortSignal.any([signal, AbortSignal.timeout(5000)]);
		const raw = await boundedWork(ports.admit(event, action, admissionSignal), admissionSignal);
		need(raw, "moment_authority", 403);
		const admission = Object.freeze({ ...raw, registration: raw.registration ? Object.freeze({ ...raw.registration }) : undefined });
		const r = admission.registration;
		need(admission.event_hash === requestHash && hex(admission.recipient_binding) && hex(admission.registration_binding), "moment_authority", 403);
		need(Number.isSafeInteger(admission.eligible_since_ms) && admission.eligible_since_ms > 0
			&& Number.isSafeInteger(admission.expires_at_ms), "moment_authority", 403);
		if (action === "send") {
			need(r, "moment_recipient", 403);
			need(r.client_type === "watchos" && r.ha_install_id === event.ha_install_id && r.ha_user_hash === event.ha_user_hash
				&& r.device_id === event.device_id && r.topic === "dev.djconnect.ios.watch"
				&& r.app_bundle_id === r.topic && ["sandbox", "production"].includes(r.apns_environment)
				&& hex(r.apns_token_hash)
				&& typeof r.apns_token_ciphertext === "string" && r.apns_token_ciphertext.length > 0
				&& typeof r.apns_token_nonce === "string" && r.apns_token_nonce.length > 0, "moment_recipient", 403);
			let categories: unknown; try { categories = JSON.parse(r.categories_json); } catch { /* deny below */ }
			need(r.disabled === 0 && r.invalid === 0 && Array.isArray(categories) && categories.includes(CATEGORY), "moment_opt_out", 403);
			// No notification backlog after opting in, reconnecting or changing owner/pairing.
			need(event.created_at_ms >= admission.eligible_since_ms, "moment_historical", 409);
		}
		let previous = 0;
		const guard = (expiry?: number) => {
			const at = ports.now();
			need(Number.isSafeInteger(at) && at >= previous, "moment_clock", 503); previous = at;
			need(!closed && !signal.aborted, "moment_cancelled", 409);
			const current: unknown = ports.assertCurrent(admission, action);
			if (current instanceof Promise) void current.catch(() => {});
			need(current === undefined, "moment_authority", 503);
			need(event.created_at_ms <= at + 5000, "moment_future", 409);
			if (expiry !== undefined) need(at < Math.min(expiry, admission.expires_at_ms), "moment_expired", 409);
			return at;
		};
		guard();
		if (action === "send") { need(r); need(await store.current(r, true, true), "moment_registration_changed", 403); guard(); }
		const scope = await sha256Hex(event.ha_install_id); guard();
		const recipient = await sha256Hex(canonical([event.ha_install_id, event.ha_user_hash, event.device_id])); guard();
		// Registration incarnation deliberately is NOT part of the operation key:
		// re-pair/token churn may never turn an old event into a new send attempt.
		const key = await sha256Hex(canonical([event.ha_install_id, event.ha_user_hash, event.device_id, event.session_id, event.moment_id])); guard();
		const publicationKey = await sha256Hex(canonical([event.ha_install_id, event.ha_user_hash, event.device_id, event.event_id])); guard();
		const admissionBinding = await sha256Hex(canonical([admission.recipient_binding, admission.registration_binding])); guard();
		return { event, admission, requestHash, scope, recipient, key, publicationKey, admissionBinding, guard };
	}
	function receipt(event: MomentEvent, row: Operation): MomentReceipt {
		return { event_id: event.event_id, state: row.state === "reserved" || row.state === "dispatching" ? "unknown" : row.state,
			provider_status: row.provider_status, expires_at_ms: row.expires_at_ms,
			retry_at_ms: row.state === "retryable" ? row.next_attempt_ms : null };
	}
	return Object.freeze({
		close() { closed = true; },
		async status(value: unknown, signal: AbortSignal): Promise<MomentReceipt | null> {
			const p = await prepare(value, "send", signal), row = (await store.get(p.key)) ?? await store.publication(p.publicationKey); p.guard();
			if (!row) return null;
			need(row.request_hash === p.requestHash && row.registration_hash === p.admissionBinding, "moment_conflict", 409);
			return receipt(p.event, row);
		},
		async cancel(value: unknown, signal: AbortSignal): Promise<MomentReceipt | null> {
			const p = await prepare(value, "cancel", signal); p.guard();
			const existing = (await store.get(p.key)) ?? await store.publication(p.publicationKey); p.guard();
			if (existing) need(existing.request_hash === p.requestHash && existing.registration_hash === p.admissionBinding, "moment_conflict", 409);
			if (!existing) {
				const row = await store.reserve({ operation_key: p.key, publication_key: p.publicationKey, scope_hash: p.scope, recipient_hash: p.recipient,
					request_hash: p.requestHash, registration_hash: p.admissionBinding,
					state: "cancelled", created_at_ms: p.event.created_at_ms, expires_at_ms: p.event.expires_at_ms,
					lease_id: crypto.randomUUID(), attempts: 1, next_attempt_ms: 0, provider_status: null }, limits, true); p.guard();
				need(row, "moment_capacity", 503);
				need(row.request_hash === p.requestHash && row.registration_hash === p.admissionBinding, "moment_conflict", 409);
			}
			await store.cancel(p.key, p.requestHash, p.admissionBinding); p.guard();
			const row = await store.get(p.key); p.guard();
			if (!row) return null;
			need(row.request_hash === p.requestHash && row.registration_hash === p.admissionBinding, "moment_conflict", 409);
			return receipt(p.event, row);
		},
		async dispatch(value: unknown, signal: AbortSignal): Promise<MomentReceipt> {
			const p = await prepare(value, "send", signal);
			const registration = p.admission.registration; need(registration, "moment_recipient", 403);
			let row = (await store.get(p.key)) ?? await store.publication(p.publicationKey); p.guard();
			const lease = crypto.randomUUID();
			if (!row) {
				const deadline = Math.min(p.event.expires_at_ms, p.admission.expires_at_ms);
				const at = p.guard(deadline);
				row = await store.reserve({ operation_key: p.key, publication_key: p.publicationKey, scope_hash: p.scope, recipient_hash: p.recipient,
					request_hash: p.requestHash, registration_hash: p.admissionBinding,
					state: "reserved", created_at_ms: at, expires_at_ms: deadline, lease_id: lease,
					attempts: 1, next_attempt_ms: at, provider_status: null }, limits); p.guard();
				if (!row) return { event_id: p.event.event_id, state: "capacity", provider_status: null, expires_at_ms: deadline, retry_at_ms: null };
			}
			need(row.request_hash === p.requestHash && row.registration_hash === p.admissionBinding, "moment_conflict", 409);
			need(p.guard() >= row.created_at_ms, "moment_clock", 503);
			if (row.state === "retryable" && row.attempts < 3) {
				const at = p.guard();
				if (at >= row.expires_at_ms) return { ...receipt(p.event, row), state: "expired", retry_at_ms: null };
				if (at < row.next_attempt_ms || !(await store.retry(row, lease, at))) return receipt(p.event, row);
				p.guard(); row = (await store.get(p.key))!; p.guard();
			}
			// Only the exact successful reservation/CAS owner may reach the provider.
			if (row.state !== "reserved" || row.lease_id !== lease) return receipt(p.event, row);
			const selected = row;
			try {
				p.guard(selected.expires_at_ms);
				const notification = await buildMomentNotification(p.event, p.admission.recipient_binding, selected.expires_at_ms); p.guard(selected.expires_at_ms);
				need(new TextEncoder().encode(JSON.stringify(notification.payload)).length <= 2048);
				if (!(await store.mark(selected, p.guard(selected.expires_at_ms), registration))) return { ...receipt(p.event, selected), state: "unknown" };
				p.guard(selected.expires_at_ms);
				const providerSignal = AbortSignal.any([signal, AbortSignal.timeout(Math.max(1, Math.min(10_000, selected.expires_at_ms - p.guard(selected.expires_at_ms))))]);
				const result = await boundedWork(ports.send(registration, notification.payload, {
					headers: notification.headers, expiresAt: selected.expires_at_ms, signal: providerSignal,
					async beforeFetch() {
						// Check both rows in one snapshot, with no further database read before fetch.
						need(await store.canDispatch(selected, registration), "moment_conflict", 409);
						const at = p.guard(selected.expires_at_ms);
						need(!providerSignal.aborted, "moment_cancelled", 409);
						return at;
					},
				}), providerSignal);
				need(Number.isSafeInteger(result.status) && (result.status === 0 || (result.status >= 100 && result.status <= 599)), "moment_provider", 503);
				need(result.retryAfterMs === undefined || (Number.isSafeInteger(result.retryAfterMs) && result.retryAfterMs >= 0 && result.retryAfterMs <= 300_001), "moment_provider", 503);
				let state: State = result.status === 200 ? "provider_accepted" : "provider_rejected";
				const retry = result.status === 429 || (result.status >= 500 && result.status <= 599);
				const at = p.guard();
				const delay = Math.max(1000 * selected.attempts, result.retryAfterMs ?? 0);
				if (result.status === 0) state = "unknown";
				else if (retry && selected.attempts < 3 && at + delay < Math.min(selected.expires_at_ms, p.admission.expires_at_ms)) state = "retryable";
				await store.finish(selected, state, result.status || null, at + delay);
				if (result.status === 410 || result.reason === "BadDeviceToken" || result.reason === "Unregistered") {
					p.guard(); const r = registration;
					await ports.db.prepare(`UPDATE registrations SET disabled=1,invalid=1,last_error_code='InvalidWatchToken'
					 WHERE id=? AND apns_token_hash=? AND ha_install_id=? AND ha_user_hash=? AND device_id=? AND topic=? AND apns_environment=?`)
						.bind(r.id, r.apns_token_hash, r.ha_install_id, r.ha_user_hash, r.device_id, r.topic, r.apns_environment).run();
				}
				p.guard(); const finished = await store.get(p.key); p.guard();
				return finished ? receipt(p.event, finished) : { ...receipt(p.event, selected), state: "unknown", provider_status: null };
			} catch {
				// Any uncertain marker/provider/write result is terminal for retries.
				try { await store.finish(selected, "unknown", null, 0); } catch { /* retain original uncertain row */ }
				return { ...receipt(p.event, selected), state: "unknown", provider_status: null, retry_at_ms: null };
			}
		},
	});
}
