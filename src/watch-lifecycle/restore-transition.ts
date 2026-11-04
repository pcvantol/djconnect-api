import type { WatchDispatchScope } from "./dispatch-identity";
import { WatchRestoreAuthority, type WatchPreferenceState } from "./restore-authority";

interface WatchTransitionPorts {
	readback(): Promise<WatchPreferenceState | null>;
	/** The owning actor checks live credentials, pairing and the original deadline synchronously. */
	assertCurrent(): void;
	/** Submit the original revision-guarded CAS without changing its signed intent. */
	submit(): Promise<unknown>;
}

function matches(left: WatchPreferenceState, right: WatchPreferenceState): boolean {
	return left.revision === right.revision && left.operation === right.operation &&
		left.body_hash === right.body_hash && left.enabled === right.enabled && left.sealed === right.sealed;
}

function assertCurrent(ports: WatchTransitionPorts): void {
	const result: unknown = ports.assertCurrent();
	if (result === undefined) return;
	void Promise.resolve(result).catch(() => undefined);
	throw new TypeError("Watch transition authority must be synchronous");
}

/** Stable actor only. Call with states derived from the already verified signed transition. */
export async function runWatchRestoreTransition(
	authority: WatchRestoreAuthority, scope: WatchDispatchScope,
	previous: WatchPreferenceState, next: WatchPreferenceState, ports: WatchTransitionPorts,
): Promise<"confirmed" | "unavailable" | "unknown"> {
	const binding = Object.freeze({ ...scope });
	const before = Object.freeze({ ...previous });
	const after = Object.freeze({ ...next });
	if (before.sealed === 1 || after.revision !== before.revision + 1) return "unavailable";
	let reserved = false;
	try {
		assertCurrent(ports);
		const observed = await ports.readback();
		if (!observed) return "unavailable";
		if (matches(observed, after)) {
			assertCurrent(ports);
			const state = authority.classifyObservation(binding, observed);
			if (state === "confirmed") return "confirmed";
			if (state !== "pending") return "unavailable";
			reserved = true;
			return authority.confirm(binding, observed) ? "confirmed" : "unknown";
		}
		if (!matches(observed, before) || authority.classifyObservation(binding, observed) !== "confirmed") return "unavailable";
		assertCurrent(ports);
		// Once reservation is attempted, an error may leave durable pending state.
		reserved = true;
		if (!await authority.begin(binding, before, after)) return "unavailable";
		assertCurrent(ports);
		if (authority.classifyObservation(binding, after) !== "pending") return "unknown";
		await ports.submit();
		const committed = await ports.readback();
		if (!committed || !matches(committed, after)) return "unknown";
		assertCurrent(ports);
		return authority.confirm(binding, committed) ? "confirmed" : "unknown";
	} catch {
		return reserved ? "unknown" : "unavailable";
	}
}
