import { sha256Hex } from "../crypto";
import type { LifecycleClaims } from "./proof";

export type WatchDispatchScope = Pick<LifecycleClaims, "installation" | "receiver" | "incarnation" | "epoch" | "key_fingerprint">;

const id = /^[A-Za-z0-9._~-]{1,160}$/;
const digest = /^[a-f0-9]{64}$/;

export function watchDispatchScopeBinding(scope: WatchDispatchScope): string | null {
	const { installation, receiver, incarnation, epoch, key_fingerprint } = scope;
	if (typeof installation !== "string" || !id.test(installation) ||
		typeof receiver !== "string" || !id.test(receiver) ||
		typeof incarnation !== "string" || !id.test(incarnation) ||
		!Number.isSafeInteger(epoch) || epoch < 1 ||
		typeof key_fingerprint !== "string" || !digest.test(key_fingerprint)) return null;
	return JSON.stringify([installation, receiver, incarnation, epoch, key_fingerprint]);
}

/** Resolve only from an independently admitted, server-resolved registry scope. */
export async function watchDispatchActorName(scope: WatchDispatchScope): Promise<string | null> {
	const binding = watchDispatchScopeBinding(scope);
	return binding === null ? null : sha256Hex("DJC-WATCH-DISPATCH-ACTOR-V1\0" + binding);
}
