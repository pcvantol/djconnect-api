import type { Fetcher } from "../apns";
import type { AppEnv } from "../types";
import { existingRelaySender, type Sender } from "../watch-moment/relay";
import { WatchDispatchFence } from "./dispatch-fence";
import { watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import { WatchRestoreAuthority, type WatchPreferenceState } from "./restore-authority";
import { readWatchPreferenceState } from "./registry-scope";

/** Closed sender inside the stable actor. Its owner must authorize the exact attempt and scope. */
export function createRestoredWatchSender(
	env: AppEnv, actor: DurableObjectState, namespace: DurableObjectNamespace,
	scope: WatchDispatchScope, now: () => number, fetcher: Fetcher = fetch,
): Sender {
	const enrolled = Object.freeze({ ...scope });
	return async (registration, payload, context) => {
		if (!context.attempt) throw new Error("watch_dispatch_unavailable");
		const { operation, lease } = context.attempt;
		const name = await watchRestoreActorName(enrolled);
		if (name === null || !actor.id.equals(namespace.idFromName(name))) throw new Error("watch_dispatch_unavailable");
		const authority = new WatchRestoreAuthority(actor.storage);
		const fence = new WatchDispatchFence(actor.storage, enrolled);
		let observed: WatchPreferenceState | null = null;
		const send = existingRelaySender(env, now, async (input, init) => {
			context.signal.throwIfAborted();
			init?.signal?.throwIfAborted();
			if (!observed) throw new Error("watch_dispatch_unavailable");
			const started = authority.start(enrolled, observed, () =>
				fence.start(enrolled, operation, lease, now(), context.expiresAt, () => fetcher(input, init)));
			if (!started?.result) throw new Error("watch_dispatch_unavailable");
			return started.result.result;
		});
		return send(registration, payload, {
			...context,
			async beforeFetch() {
				observed = await readWatchPreferenceState(env.DB, enrolled);
				if (!observed) throw new Error("watch_dispatch_unavailable");
				return context.beforeFetch();
			},
		});
	};
}
