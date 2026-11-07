import { sendApns, type Fetcher } from "../apns";
import { sha256Hex } from "../crypto";
import type { AppEnv, Registration } from "../types";
import { need } from "./wire";

export interface ProviderReply { status: number; reason?: string; retryAfterMs?: number }
export interface SendContext {
	headers: Record<string, string>; expiresAt: number; signal: AbortSignal;
	attempt?: Readonly<{ operation: string; lease: string }>;
	/** Checks the registration and operation together after decryption and signing. */
	beforeFetch(): Promise<number>;
	/** Rechecks owner authority and returns current time with no await before provider entry. */
	assertBeforeProvider(): number;
}
export type Sender = (registration: Registration, payload: Record<string, unknown>, context: SendContext) => Promise<ProviderReply>;

/** Uses the existing key/token/decryption/alert sender; no second push engine. */
export function existingRelaySender(env: AppEnv, now: () => number, fetcher: Fetcher = fetch): Sender {
	return async (registration, payload, context) => {
		let retryAfterMs: number | undefined;
		const bounded: Fetcher = async (input, init) => {
			const url = new URL(input instanceof Request ? input.url : String(input));
			const expected = registration.apns_environment === "sandbox" ? "https://api.sandbox.push.apple.com" : "https://api.push.apple.com";
			need(url.origin === expected && !url.search && !url.hash && !url.username && !url.password, "moment_provider_target", 503);
			const token = url.pathname.slice("/3/device/".length);
			need(url.pathname.startsWith("/3/device/") && /^(?:[a-fA-F0-9]{2}){16,2048}$/.test(token), "moment_provider_target", 503);
			need(await sha256Hex(token) === registration.apns_token_hash, "moment_token_binding", 503);
			await context.beforeFetch();
			const headers = new Headers(init?.headers);
			for (const [key, value] of Object.entries(context.headers)) headers.set(key, value);
			const admittedAt = context.assertBeforeProvider();
			need(Number.isSafeInteger(admittedAt), "moment_clock", 503);
			const remaining = context.expiresAt - admittedAt;
			need(remaining > 0 && !context.signal.aborted, "moment_expired", 409);
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
