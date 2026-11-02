import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import schema from "../src/watch-moment/schema.sql?raw";
import { encryptSecret, sha256Hex } from "../src/crypto";
import { buildMomentNotification } from "../src/watch-moment/payload";
import { existingRelaySender, type Sender } from "../src/watch-moment/relay";
import { createMomentTransport, type Admission, type MomentPorts } from "../src/watch-moment/service";
import { canonical, CATEGORY, decodeEvent, readEvent, VERSION, type MomentEvent } from "../src/watch-moment/wire";
import type { AppEnv, Registration } from "../src/types";
import proposal from "../docs/push/watch-moment-alert-proposal-v1.json";

const NOW = proposal.shared_synthetic_fixture.now_ms;
const signal = () => new AbortController().signal;
const key = btoa("0123456789abcdef0123456789abcdef");
const event = (overrides: Partial<MomentEvent> = {}): MomentEvent => ({ ...proposal.shared_synthetic_fixture.event,
	version: VERSION, event_type: "dj_moment_published", ...overrides });
let registration: Registration;
let now: number, allowed: boolean, admittedUntil: number, eligibleSince: number, registrationBinding: string;
let publications: Map<string, string>;
const publish = (overrides: Partial<MomentEvent> = {}) => {
	const value = event({ ...(overrides.event_id ? { moment_id: "moment-" + overrides.event_id } : {}), ...overrides });
	publications.set(value.event_id, canonical(value)); return value;
};

function setup(overrides: Partial<MomentPorts> = {}) {
	const send = vi.fn<Sender>(async (_r, _body, context) => { await context.beforeFetch(); return { status: 200 }; });
	const ports: MomentPorts = { db: env.DB, now: () => now,
		async admit(e) {
			if (publications.get(e.event_id) !== canonical(e)) throw Error("synthetic publication not admitted");
			return { event_hash: await sha256Hex(canonical(e)), recipient_binding: "b".repeat(64),
				registration_binding: registrationBinding, eligible_since_ms: eligibleSince,
				expires_at_ms: admittedUntil, registration };
		},
		assertCurrent(_admission: Admission, action) { if (!allowed && action !== "cancel") throw Error("synthetic currentness revoked"); },
		send, limits: { capacity: 64, installationCapacity: 32, recipientBurst: 10 }, ...overrides };
	return { service: createMomentTransport(ports), send, ports };
}

describe("Watch Moment transport — actual local SQLite, synthetic original authority/provider", () => {
	beforeAll(async () => {
		for (const part of schema.split(";").map(v => v.trim()).filter(Boolean)) await env.DB.prepare(part).run();
		await env.DB.prepare(`CREATE TABLE registrations(id TEXT PRIMARY KEY,apns_token_hash TEXT,ha_install_id TEXT,ha_user_hash TEXT,
		 device_id TEXT,topic TEXT,apns_environment TEXT,disabled INTEGER,invalid INTEGER,last_error_code TEXT,
		 client_type TEXT,app_bundle_id TEXT,categories_json TEXT,apns_token_ciphertext TEXT,apns_token_nonce TEXT)`).run();
	});
	beforeEach(async () => {
		await env.DB.exec("DELETE FROM watch_moment_operations; DELETE FROM registrations");
		now = NOW; allowed = true; eligibleSince = NOW - 1000; admittedUntil = NOW + 60_000; registrationBinding = "c".repeat(64); publications = new Map();
		const encrypted = await encryptSecret("e".repeat(64), key);
		registration = { id: "example-registration", ha_install_id: "example-install", ha_user_hash: "a".repeat(64), device_id: "example-watch", client_type: "watchos",
			apns_token_hash: await sha256Hex("e".repeat(64)), apns_token: null, apns_token_ciphertext: encrypted.ciphertext, apns_token_nonce: encrypted.nonce,
			apns_token_key_version: encrypted.keyVersion, apns_environment: "sandbox", topic: "dev.djconnect.ios.watch", app_bundle_id: "dev.djconnect.ios.watch",
			app_version: "example", locale: "nl-NL", categories_json: JSON.stringify([CATEGORY]), disabled: 0, invalid: 0,
			created_at: "example", updated_at: "example", last_success_at: null, last_error_code: null };
		await env.DB.prepare("INSERT INTO registrations VALUES(?,?,?,?,?,?,?,0,0,NULL,?,?,?,?,?)")
			.bind(registration.id, registration.apns_token_hash, registration.ha_install_id, registration.ha_user_hash,
				registration.device_id, registration.topic, registration.apns_environment, registration.client_type,
				registration.app_bundle_id, registration.categories_json, registration.apns_token_ciphertext, registration.apns_token_nonce).run();
	});

	it("sends a generic exact-target alert and never treats provider acceptance as device delivery", async () => {
		const { service, send } = setup(), e = publish();
		const r = await service.dispatch(e, signal());
		expect(r).toMatchObject({ state: "provider_accepted", provider_status: 200, expires_at_ms: e.expires_at_ms });
		expect(send).toHaveBeenCalledOnce();
		const body = send.mock.calls[0]![1];
		const expected = proposal.shared_synthetic_fixture.expected_notification;
		expect(body).toMatchObject({ aps: { alert: { title: expected.title, body: expected.body } },
			open_target: expected.open_target, session_id: expected.session_id, moment_id: expected.moment_id });
		expect(body).toEqual(proposal.shared_synthetic_fixture.expected_apns.body);
		for (const privateField of ["ha_install_id", "ha_user_hash", "device_id", "token", "text", "audio", "artwork", "url"]) expect(body).not.toHaveProperty(privateField);
		expect(r).not.toHaveProperty("delivered");
	});
	it.each(["en", "nl", "de", "fr", "es"])("uses a generic original locale (%s)", async locale => {
		const n = await buildMomentNotification(event({ locale }), "b".repeat(64), NOW + 60_000);
		expect(n.payload.aps.alert.body.length).toBeGreaterThan(10);
		expect(JSON.stringify(n.payload)).not.toContain("example-watch");
	});
	it("groups a Session but only collapses retries of the same event", async () => {
		const a = await buildMomentNotification(event(), "b".repeat(64), NOW + 60_000);
		const same = await buildMomentNotification(event(), "b".repeat(64), NOW + 60_000);
		const next = await buildMomentNotification(event({ event_id: "example-publication-2", moment_id: "example-moment-2" }), "b".repeat(64), NOW + 60_000);
		expect(a.headers["apns-collapse-id"]).toBe(same.headers["apns-collapse-id"]);
		expect(a.headers["apns-collapse-id"]).not.toBe(next.headers["apns-collapse-id"]);
		expect(a.payload.aps["thread-id"]).toBe(next.payload.aps["thread-id"]);
	});
	it("dedupes concurrent producers and reconstruction over actual durable rows", async () => {
		const first = setup(), e = publish();
		await Promise.all([first.service.dispatch(e, signal()), first.service.dispatch(e, signal()), first.service.dispatch(e, signal())]);
		expect(first.send).toHaveBeenCalledOnce();
		const second = setup(); expect((await second.service.dispatch(e, signal())).state).toBe("provider_accepted");
		expect(second.send).not.toHaveBeenCalled();
	});
	it.each(["session_id", "moment_id", "locale", "expires_at_ms"] as const)("refuses changing %s under an original publication ID", async field => {
		const { service, send } = setup(), e = publish(); await service.dispatch(e, signal());
		const changed = { ...e, [field]: field === "expires_at_ms" ? NOW + 65_000 : field === "locale" ? "fr" : "example-changed" } as MomentEvent;
		publications.set(changed.event_id, canonical(changed));
		await expect(service.dispatch(changed, signal())).rejects.toThrow("moment_conflict"); expect(send).toHaveBeenCalledOnce();
	});
	it("rejects a fresh event ID for the same original Moment and reusing an ID for another Moment", async () => {
		const { service, send } = setup(), original = publish(); await service.dispatch(original, signal());
		const renamed = publish({ event_id: "renamed-event", moment_id: original.moment_id });
		await expect(service.dispatch(renamed, signal())).rejects.toThrow("moment_conflict");
		const rebound = publish({ moment_id: "different-original-moment" });
		await expect(service.dispatch(rebound, signal())).rejects.toThrow("moment_conflict"); expect(send).toHaveBeenCalledOnce();
	});
	it.each(["ha_install_id", "ha_user_hash", "device_id", "topic", "app_bundle_id", "client_type", "apns_environment"])("rejects wrong recipient %s", async field => {
		const { service, send } = setup(), e = publish();
		(registration as unknown as Record<string, unknown>)[field] = field === "ha_user_hash" ? "f".repeat(64) : "example-wrong";
		await expect(service.dispatch(e, signal())).rejects.toThrow("moment_recipient"); expect(send).not.toHaveBeenCalled();
	});
	it.each(["disabled", "invalid", "opt-out"])("stops new sends after %s", async field => {
		const { service, send } = setup(), e = publish();
		if (field === "opt-out") registration.categories_json = "[]"; else (registration as unknown as Record<string, unknown>)[field] = 1;
		await expect(service.dispatch(e, signal())).rejects.toThrow("moment_opt_out"); expect(send).not.toHaveBeenCalled();
	});
	it("does not replay publications from before opt-in/pairing", async () => {
		const { service, send } = setup(), e = publish(); eligibleSince = NOW + 1;
		await expect(service.dispatch(e, signal())).rejects.toThrow("moment_historical"); expect(send).not.toHaveBeenCalled();
	});
	it("rejects expired and future publication clocks", async () => {
		const { service, send } = setup();
		now = NOW + 60_001; await expect(service.dispatch(publish(), signal())).rejects.toThrow("moment_expired");
		now = NOW; await expect(service.dispatch(publish({ created_at_ms: NOW + 10_000 }), signal())).rejects.toThrow("moment_future");
		expect(send).not.toHaveBeenCalled();
	});
	it("checks original authority and does not allow async final guards", async () => {
		const e = publish(); allowed = false;
		await expect(setup().service.dispatch(e, signal())).rejects.toThrow("synthetic currentness revoked");
		const bad = setup({ assertCurrent: (() => Promise.resolve()) as unknown as MomentPorts["assertCurrent"] });
		await expect(bad.service.dispatch(e, signal())).rejects.toThrow("moment_authority"); expect(bad.send).not.toHaveBeenCalled();
	});
	it("rejects a supplier receipt for a different original publication", async () => {
		const base = setup(), e = publish();
		const { service, send } = setup({ admit: async (v, a, s) => ({ ...await base.ports.admit(v, a, s), event_hash: "f".repeat(64) }) });
		await expect(service.dispatch(e, signal())).rejects.toThrow("moment_authority"); expect(send).not.toHaveBeenCalled();
	});
	it("rejects a backwards local clock without reaching provider effects", async () => {
		let reads = 0;
		const { service, send } = setup({ now: () => ++reads === 1 ? NOW : NOW - 1 });
		await expect(service.dispatch(publish(), signal())).rejects.toThrow("moment_clock"); expect(send).not.toHaveBeenCalled();
	});
	it("rechecks currentness immediately at the sender after async preparation", async () => {
		let effects = 0;
		const { service } = setup({ send: async (_r, _p, ctx) => { allowed = false; await ctx.beforeFetch(); effects++; return { status: 200 }; } });
		expect((await service.dispatch(publish(), signal())).state).toBe("unknown"); expect(effects).toBe(0);
	});
	it.each(["opt-out", "new-token", "other-owner"])("checks actual shared registry state at provider handoff after %s", async change => {
		let effects = 0;
		const { service } = setup({ send: async (_r, _p, ctx) => {
			const columns = { "opt-out": ["categories_json", "[]"], "new-token": ["apns_token_hash", "f".repeat(64)], "other-owner": ["ha_user_hash", "f".repeat(64)] };
			const [column, value] = columns[change as keyof typeof columns];
			await env.DB.prepare(`UPDATE registrations SET ${column}=? WHERE id=?`).bind(value, registration.id).run();
			await ctx.beforeFetch(); effects++; return { status: 200 };
		} });
		expect((await service.dispatch(publish(), signal())).state).toBe("unknown"); expect(effects).toBe(0);
	});
	it("does not admit an encrypted token substituted by the authority adapter", async () => {
		registration.apns_token_ciphertext = "example-substituted-ciphertext";
		const { service, send } = setup(); await expect(service.dispatch(publish(), signal())).rejects.toThrow("moment_registration_changed"); expect(send).not.toHaveBeenCalled();
	});
	it("makes timeouts/unknown outcomes terminal for resend", async () => {
		const sender = vi.fn(async () => { throw Error("synthetic provider timeout"); });
		const { service } = setup({ send: sender }), e = publish();
		expect((await service.dispatch(e, signal())).state).toBe("unknown");
		expect((await service.dispatch(e, signal())).state).toBe("unknown"); expect(sender).toHaveBeenCalledOnce();
	});
	it.each([429, 500, 503])( "uses the same original event and deadline for bounded known-rejection retries (%s)", async status => {
		const sender = vi.fn<Sender>(async (_r, _p, ctx) => { await ctx.beforeFetch(); return { status, retryAfterMs: 1500 }; });
		const { service } = setup({ send: sender }), e = publish();
		const one = await service.dispatch(e, signal()); expect(one.state).toBe("retryable");
		await service.dispatch(e, signal()); expect(sender).toHaveBeenCalledTimes(1);
		now += 1500; const two = await service.dispatch(e, signal()); expect(two.state).toBe("retryable");
		now += 2000; const three = await service.dispatch(e, signal()); expect(three.state).toBe("provider_rejected");
		await service.dispatch(e, signal()); expect(sender).toHaveBeenCalledTimes(3);
		for (const call of sender.mock.calls) expect(call[2].expiresAt).toBe(e.expires_at_ms);
	});
	it("does not extend the first admitted deadline when a later supplier lease is longer", async () => {
		const sender = vi.fn<Sender>(async (_r, _p, ctx) => { await ctx.beforeFetch(); return { status: 503 }; });
		const { service } = setup({ send: sender }), e = publish(); admittedUntil = NOW + 3000;
		await service.dispatch(e, signal()); admittedUntil = NOW + 50_000; now += 3001;
		expect((await service.dispatch(e, signal())).state).toBe("expired"); expect(sender).toHaveBeenCalledOnce();
	});
	it("does not retry earlier than a provider delay beyond the original lifetime", async () => {
		const sender = vi.fn(async () => ({ status: 429, retryAfterMs: 120_000 }));
		const { service } = setup({ send: sender }), e = publish();
		expect((await service.dispatch(e, signal())).state).toBe("provider_rejected");
		now += 59_000; await service.dispatch(e, signal()); expect(sender).toHaveBeenCalledOnce();
	});
	it("does not rebind an operation after token/registration incarnation changes", async () => {
		const { service, send } = setup(), e = publish(); await service.dispatch(e, signal()); registrationBinding = "f".repeat(64);
		await expect(service.dispatch(e, signal())).rejects.toThrow("moment_conflict"); expect(send).toHaveBeenCalledOnce();
	});
	it("keeps pre-arrival cancellation tombstones and supports withdrawal after opt-out", async () => {
		const { service, send } = setup(), e = publish(); allowed = false; registration.disabled = 1; registration.categories_json = "[]";
		expect((await service.cancel(e, signal()))?.state).toBe("cancelled");
		allowed = true; registration.disabled = 0; registration.categories_json = JSON.stringify([CATEGORY]);
		expect((await service.dispatch(e, signal())).state).toBe("cancelled"); expect(send).not.toHaveBeenCalled();
	});
	it("withdraws a retryable event without replacing its original operation", async () => {
		const sender = vi.fn(async () => ({ status: 503 })), { service } = setup({ send: sender }), e = publish();
		await service.dispatch(e, signal()); expect((await service.cancel(e, signal()))?.state).toBe("cancelled");
		now += 5000; expect((await service.dispatch(e, signal())).state).toBe("cancelled"); expect(sender).toHaveBeenCalledOnce();
	});
	it("retains original withdrawal authority after registry ownership changes, without an active credential", async () => {
		const base = setup({ send: async () => ({ status: 503 }) }), e = publish();
		await base.service.dispatch(e, signal());
		const original = await base.ports.admit(e, "cancel", signal());
		await env.DB.prepare("UPDATE registrations SET ha_user_hash=?,disabled=1 WHERE id=?").bind("f".repeat(64), registration.id).run();
		const { service, send } = setup({ admit: async () => ({ ...original, registration: undefined }) });
		expect((await service.cancel(e, signal()))?.state).toBe("cancelled"); expect(send).not.toHaveBeenCalled();
		await expect(service.dispatch(e, signal())).rejects.toThrow("moment_recipient");
	});
	it("reserves bounded capacity for cancellation, retaining earlier outcomes", async () => {
		const { service, send } = setup({ limits: { capacity: 3, installationCapacity: 3, recipientBurst: 10 } });
		await service.dispatch(publish({ event_id: "event-1" }), signal()); await service.dispatch(publish({ event_id: "event-2" }), signal());
		const last = publish({ event_id: "event-3" }); expect((await service.dispatch(last, signal())).state).toBe("capacity");
		expect((await service.cancel(last, signal()))?.state).toBe("cancelled"); expect(send).toHaveBeenCalledTimes(2);
		expect((await env.DB.prepare("SELECT count(*) AS n FROM watch_moment_operations").first<{ n: number }>())?.n).toBe(3);
	});
	it("bounds per-recipient publication bursts without overwriting original dedupe rows", async () => {
		const { service, send } = setup({ limits: { capacity: 64, installationCapacity: 32, recipientBurst: 2 } });
		await service.dispatch(publish({ event_id: "event-1" }), signal()); await service.dispatch(publish({ event_id: "event-2" }), signal());
		expect((await service.dispatch(publish({ event_id: "event-3" }), signal())).state).toBe("capacity"); expect(send).toHaveBeenCalledTimes(2);
	});
	it("invalidates only the exact current failed token binding", async () => {
		const { service } = setup({ send: async () => ({ status: 410, reason: "Unregistered" }) });
		await service.dispatch(publish(), signal());
		expect((await env.DB.prepare("SELECT disabled,invalid FROM registrations WHERE id=?").bind(registration.id).first())).toMatchObject({ disabled: 1, invalid: 1 });
	});
	it("does not invalidate a replacement token due to an old provider callback", async () => {
		const { service } = setup({ send: async () => {
			await env.DB.prepare("UPDATE registrations SET apns_token_hash=? WHERE id=?").bind("f".repeat(64), registration.id).run();
			return { status: 410, reason: "Unregistered" };
		} });
		await service.dispatch(publish(), signal());
		expect((await env.DB.prepare("SELECT disabled FROM registrations WHERE id=?").bind(registration.id).first())).toMatchObject({ disabled: 0 });
	});
	it("keeps all payload/identity/token text out of durable operation rows", async () => {
		const { service } = setup(); await service.dispatch(publish(), signal());
		const rows = JSON.stringify((await env.DB.prepare("SELECT * FROM watch_moment_operations").all()).results);
		for (const value of ["example-install", "example-watch", "example-session", "example-moment", "Je DJ", registration.apns_token_ciphertext!]) expect(rows).not.toContain(value);
	});
	it("reuses actual token decryption/provider signing and bounded alert headers with mocked provider egress", async () => {
		const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
		const bytes = await crypto.subtle.exportKey("pkcs8", pair.privateKey) as ArrayBuffer;
		const privateKey = ["-----BEGIN", " PRIVATE KEY-----\n", btoa(String.fromCharCode(...new Uint8Array(bytes))), "\n-----END", " PRIVATE KEY-----"].join("");
		const fetcher = vi.fn(async (_u: RequestInfo | URL, _init?: RequestInit) => new Response("{}", { status: 200 }));
		const appEnv = { APNS_TEAM_ID: "example", APNS_KEY_ID: "example", APNS_PRIVATE_KEY: privateKey,
			APNS_TOKEN_ENCRYPTION_KEY: key, DJCONNECT_SMOKE_TEST_MODE: "enabled" } as AppEnv;
		const { service } = setup({ send: existingRelaySender(appEnv, () => now, fetcher) });
		expect((await service.dispatch(publish(), signal())).state).toBe("provider_accepted");
		expect(fetcher).toHaveBeenCalledOnce(); expect(String(fetcher.mock.calls[0]![0])).toBe("https://api.sandbox.push.apple.com/3/device/" + "e".repeat(64));
		const init = fetcher.mock.calls[0]![1] as RequestInit, h = new Headers(init.headers);
		expect(h.get("apns-topic")).toBe("dev.djconnect.ios.watch"); expect(h.get("apns-push-type")).toBe("alert");
		expect(h.get("apns-priority")).toBe("10"); expect(h.get("apns-expiration")).toBe(String((NOW + 60_000) / 1000));
		expect(init.signal).toBeInstanceOf(AbortSignal); expect(init.redirect).toBe("error");
		const token = h.get("authorization")!.slice("bearer ".length).split(".");
		const bytesOf = (v: string) => Uint8Array.from(atob(v.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
		expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pair.publicKey, bytesOf(token[2]!), new TextEncoder().encode(token.slice(0, 2).join(".")))).toBe(true);
		registration.apns_token_hash = "f".repeat(64);
		await env.DB.prepare("UPDATE registrations SET apns_token_hash=? WHERE id=?").bind(registration.apns_token_hash, registration.id).run();
		expect((await service.dispatch(publish({ event_id: "mismatched-token" }), signal())).state).toBe("unknown");
		expect(fetcher).toHaveBeenCalledOnce();
	});
	it.each(["url", "audio", "text", "token", "open_target", "external_relay"])("rejects unknown/private wire field %s", field => {
		expect(() => decodeEvent({ ...event(), [field]: "example" })).toThrow("moment_invalid");
	});
	it("rejects overlong windows, route injection and accessor fields", () => {
		expect(() => decodeEvent(event({ expires_at_ms: NOW + 300_001 }))).toThrow();
		expect(() => decodeEvent(event({ moment_id: "https://example.invalid/other-owner" }))).toThrow();
		const e = event(); Object.defineProperty(e, "moment_id", { get() { throw Error("must not invoke"); }, enumerable: true });
		expect(() => decodeEvent(e)).toThrow("moment_invalid");
	});
	it("strictly rejects duplicate JSON keys, invalid UTF-8 and oversized bodies", async () => {
		const make = (body: string | Uint8Array) => new Request("https://example.invalid/", { method: "POST", headers: { "content-type": "application/json" }, body });
		await expect(readEvent(make(JSON.stringify(event()).replace('"moment_id":"example-moment"', '"moment_id":"example-moment","moment_id":"other"')))).rejects.toThrow("moment_json");
		await expect(readEvent(make(new Uint8Array([0xff])))).rejects.toThrow("moment_json");
		await expect(readEvent(make(" ".repeat(2049)))).rejects.toThrow("moment_size");
		expect(await readEvent(make(JSON.stringify(event())))).toEqual(event());
	});
	it("rejects cancelled/closed requests without provider effects", async () => {
		const { service, send } = setup(), e = publish(); const controller = new AbortController(); controller.abort();
		await expect(service.dispatch(e, controller.signal)).rejects.toThrow("moment_cancelled");
		service.close(); await expect(service.dispatch(e, signal())).rejects.toThrow("moment_cancelled"); expect(send).not.toHaveBeenCalled();
	});
	it("bounds an in-flight authority wait even when the supplier ignores cancellation", async () => {
		let entered!: () => void; const seen = new Promise<void>(resolve => { entered = resolve; });
		const { service, send } = setup({ admit: async () => { entered(); return await new Promise<Admission>(() => {}); } });
		const controller = new AbortController(), pending = service.dispatch(publish(), controller.signal);
		await seen; controller.abort(); await expect(pending).rejects.toThrow("moment_work_cancelled"); expect(send).not.toHaveBeenCalled();
	});
	it("makes a cancelled in-flight provider operation unknown and never retries it", async () => {
		let entered!: () => void; const seen = new Promise<void>(resolve => { entered = resolve; });
		const sender = vi.fn<Sender>(async () => { entered(); return await new Promise(() => {}); });
		const { service } = setup({ send: sender }), controller = new AbortController(), e = publish();
		const pending = service.dispatch(e, controller.signal); await seen; controller.abort();
		expect((await pending).state).toBe("unknown"); expect((await service.dispatch(e, signal())).state).toBe("unknown"); expect(sender).toHaveBeenCalledOnce();
	});
	it("does not treat a rejected async final-authority guard as a valid authority", async () => {
		const { service, send } = setup({ assertCurrent: (() => Promise.reject(new Error("synthetic rejected authority"))) as unknown as MomentPorts["assertCurrent"] });
		await expect(service.dispatch(publish(), signal())).rejects.toThrow("moment_authority"); expect(send).not.toHaveBeenCalled();
	});
});
