import type { WatchDispatchScope } from "./dispatch-identity";
import { applyWatchPairing } from "./pairing";
import { verifyLifecycleProof, type LifecycleClaims } from "./proof";

export interface WatchRetirementPorts {
	db: D1Database;
	audience: string;
	now(): number;
	/** Resolve a key from trusted enrollment for the exact server-resolved scope. */
	resolveEnrolledKey(claims: WatchDispatchScope, signal: AbortSignal): Promise<Uint8Array | null>;
	/** Consult authority independent of the D1 snapshot. Unknown must deny. */
	isRestoreCurrent(claims: LifecycleClaims, signal: AbortSignal): Promise<boolean>;
	/** Persist an exact, idempotent fence before acknowledging. */
	blockDispatch(claims: LifecycleClaims, bodyHash: string, signal: AbortSignal): Promise<boolean>;
	/** Read a currently effective fence bound to the exact retirement operation and body. */
	hasDispatchBlock(claims: LifecycleClaims, operation: string, bodyHash: string, signal: AbortSignal): Promise<boolean>;
}

export type WatchRetirementOutcome = "denied" | "unknown" | "committed";

/** Private composition. The owning Worker must supply all authority and actor ports. */
export function createWatchRetirement(ports: WatchRetirementPorts) {
	return async (
		body: Uint8Array, signature: Uint8Array, candidate: WatchDispatchScope, signal: AbortSignal,
	): Promise<WatchRetirementOutcome> => {
		if (body.length > 2048 || signature.length !== 64) return "denied";
		const original = new Uint8Array(body);
		const proof = new Uint8Array(signature);
		const scope = Object.freeze({ ...candidate });
		let outcomeMayBeUncertain = false;
		try {
			signal.throwIfAborted();
			const key = await ports.resolveEnrolledKey(scope, signal);
			if (!key) return "denied";
			const claims = await verifyLifecycleProof(original, proof, key, ports.audience, ports.now());
			if (!claims || (claims.action !== "retire" && claims.action !== "lifecycle-status")
				|| claims.installation !== scope.installation || claims.receiver !== scope.receiver
				|| claims.incarnation !== scope.incarnation || claims.epoch !== scope.epoch
				|| claims.key_fingerprint !== scope.key_fingerprint) return "denied";
			if (await ports.isRestoreCurrent(claims, signal) !== true) return "denied";
			signal.throwIfAborted();
			if (claims.action === "lifecycle-status") {
				outcomeMayBeUncertain = true;
				const receipt = await applyWatchPairing(ports.db, original, proof, key, ports.audience, ports.now());
				if (!receipt || !("state" in receipt) || receipt.state !== "committed_current"
					|| receipt.retired !== 1 || receipt.incarnation !== claims.incarnation
					|| receipt.operation !== claims.target_operation || receipt.body_hash !== claims.target_body_sha256) return "unknown";
				signal.throwIfAborted();
				if (await ports.hasDispatchBlock(claims, receipt.operation, receipt.body_hash, signal) !== true) return "unknown";
				if (await ports.isRestoreCurrent(claims, signal) !== true) return "unknown";
				signal.throwIfAborted();
				return ports.now() < claims.expiry ? "committed" : "unknown";
			}
			const bodyHash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", original)),
				byte => byte.toString(16).padStart(2, "0")).join("");
			if (ports.now() >= claims.expiry) return "denied";
			outcomeMayBeUncertain = true;
			if (await ports.blockDispatch(claims, bodyHash, signal) !== true) return "unknown";
			signal.throwIfAborted();
			if (await ports.isRestoreCurrent(claims, signal) !== true) return "unknown";
			signal.throwIfAborted();
			const receipt = await applyWatchPairing(ports.db, original, proof, key, ports.audience, ports.now());
			if (!receipt || !("lifecycle_operation" in receipt) || receipt.lifecycle_operation !== claims.operation
				|| receipt.incarnation !== claims.incarnation || receipt.retired !== 1 || receipt.enabled !== 0) return "unknown";
			if (await ports.isRestoreCurrent(claims, signal) !== true) return "unknown";
			signal.throwIfAborted();
			return ports.now() < claims.expiry ? "committed" : "unknown";
		} catch {
			return outcomeMayBeUncertain ? "unknown" : "denied";
		}
	};
}
