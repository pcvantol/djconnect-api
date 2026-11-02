import { sendApns, type Fetcher } from "../apns";
import type { AppEnv, Registration } from "../types";
import { need } from "./wire";

export interface ProviderReply { status: number; reason?: string; retryAfterMs?: number }
export interface SendContext {
	headers: Record<string, string>; expiresAt: number; signal: AbortSignal;
	/** Must run after decryption/signing, immediately before the provider effect. */
	beforeFetch(): Promise<number>;
}
export type Sender = (registration: Registration, payload: Record<string, unknown>, context: SendContext) => Promise<ProviderReply>;

/** Uses the existing key/token/decryption/alert sender; no second push engine. */
export function existingRelaySender(env: AppEnv, now: () => number, fetcher: Fetcher = fetch): Sender {
	return async (registration, payload, context) => {
		let retryAfterMs: number | undefined;
		const bounded: Fetcher = async (input, init) => {
			const admittedAt = await context.beforeFetch();
			need(Number.isSafeInteger(admittedAt), "moment_clock", 503);
			const remaining = context.expiresAt - admittedAt;
			need(remaining > 0 && !context.signal.aborted, "moment_expired", 409);
			const headers = new Headers(init?.headers);
			for (const [key, value] of Object.entries(context.headers)) headers.set(key, value);
			const result = await fetcher(input, { ...init, headers, redirect: "error",
				signal: AbortSignal.any([context.signal, AbortSignal.timeout(Math.max(1, Math.min(10_000, remaining)))]) });
			const retry = result.headers.get("retry-after");
			if (retry && /^\d{1,9}$/.test(retry)) retryAfterMs = Math.min(300_001, Number(retry) * 1000);
			else if (retry && retry.length <= 128) {
				const until = Date.parse(retry);
				if (Number.isFinite(until)) retryAfterMs = Math.min(300_001, Math.max(0, until - now()));
			}
			return result;
		};
		// The new transport must always reach the controlled sender, including test fixtures.
		const result = await sendApns({ ...env, DJCONNECT_SMOKE_TEST_MODE: "disabled" }, registration, payload, bounded);
		return { status: result.status, reason: result.reason, retryAfterMs };
	};
}
