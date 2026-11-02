import { canonical, parseStrictJson } from "../surface-push/wire";
export { canonical };

/** Proposed additive contract. No production endpoint or consumer adoption is implied. */
export const VERSION = "djc-watch-moment/1" as const;
export const CATEGORY = "dj_moments_v1";
export const MAX_TTL_MS = 300_000;
export const MAX_BODY_BYTES = 2048;
export class MomentError extends Error {
	constructor(public readonly code: string, public readonly status = 400) { super(code); }
}
export function need(value: unknown, code = "moment_invalid", status = 400): asserts value {
	if (!value) throw new MomentError(code, status);
}
export interface MomentEvent {
	version: typeof VERSION;
	event_type: "dj_moment_published";
	event_id: string;
	ha_install_id: string;
	ha_user_hash: string;
	device_id: string;
	session_id: string;
	moment_id: string;
	created_at_ms: number;
	expires_at_ms: number;
	locale: string;
}
const fields = ["version", "event_type", "event_id", "ha_install_id", "ha_user_hash", "device_id", "session_id", "moment_id", "created_at_ms", "expires_at_ms", "locale"];
export function decodeEvent(value: unknown): Readonly<MomentEvent> {
	need(value !== null && typeof value === "object" && !Array.isArray(value));
	need(Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
	need(Reflect.ownKeys(value).length === fields.length);
	for (const key of fields) {
		const d = Object.getOwnPropertyDescriptor(value, key);
		need(d && Object.hasOwn(d, "value") && d.enumerable);
	}
	const v = value as Record<string, unknown>;
	need(v.version === VERSION && v.event_type === "dj_moment_published");
	for (const key of ["event_id", "ha_install_id", "device_id", "session_id", "moment_id"]) {
		need(typeof v[key] === "string" && /^[A-Za-z0-9_-]{1,160}$/.test(v[key] as string));
	}
	need(typeof v.ha_user_hash === "string" && /^[a-f0-9]{64}$/.test(v.ha_user_hash));
	need(Number.isSafeInteger(v.created_at_ms) && (v.created_at_ms as number) > 0);
	need(Number.isSafeInteger(v.expires_at_ms) && (v.expires_at_ms as number) > (v.created_at_ms as number));
	need((v.expires_at_ms as number) - (v.created_at_ms as number) <= MAX_TTL_MS);
	need(typeof v.locale === "string" && /^[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{2,8}){0,2}$/.test(v.locale));
	return Object.freeze({ ...v }) as unknown as Readonly<MomentEvent>;
}

/** Strict, duplicate-key rejecting, byte- and time-bounded read; no token/content fields. */
export async function readEvent(request: Request): Promise<Readonly<MomentEvent>> {
	need(request.headers.get("content-type")?.trim().toLowerCase() === "application/json", "moment_media", 415);
	need(!request.headers.has("content-encoding"));
	const reader = request.body?.getReader(); need(reader);
	const signal = AbortSignal.any([request.signal, AbortSignal.timeout(3000)]);
	const abort = () => { void reader.cancel().catch(() => {}); };
	signal.addEventListener("abort", abort, { once: true });
	const chunks: Uint8Array[] = []; let size = 0;
	try {
		need(!signal.aborted, "moment_cancelled", 408);
		for (;;) {
			const item = await reader.read(); need(!signal.aborted, "moment_cancelled", 408);
			if (item.done) break;
			size += item.value.length; need(size <= MAX_BODY_BYTES, "moment_size", 413);
			chunks.push(item.value);
		}
		const bytes = new Uint8Array(size); let at = 0;
		for (const chunk of chunks) { bytes.set(chunk, at); at += chunk.length; }
		try { return decodeEvent(parseStrictJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes))); }
		catch (e) { if (e instanceof MomentError) throw e; throw new MomentError("moment_json"); }
	} finally { signal.removeEventListener("abort", abort); void reader.cancel().catch(() => {}); }
}
