import type { Fetcher } from "../apns";
import type { AppEnv } from "../types";
import { existingRelaySender, type Sender } from "../watch-moment/relay";
import { WatchDispatchFence } from "./dispatch-fence";
import { watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import { WatchRestoreAuthority } from "./restore-authority";

interface DispatchAttempt {
	operation: string;
	lease: string;
}

/** Closed sender inside the stable actor. Its owner must authorize the exact attempt and scope. */
export function createRestoredWatchSender(
	env: AppEnv, actor: DurableObjectState, namespace: DurableObjectNamespace,
	scope: WatchDispatchScope, attempt: Readonly<DispatchAttempt>, now: () => number, fetcher: Fetcher = fetch,
): Sender {
	const enrolled = Object.freeze({ ...scope });
	const { operation, lease } = attempt;
	return async (registration, payload, context) => {
		const name = await watchRestoreActorName(enrolled);
		if (name === null || !actor.id.equals(namespace.idFromName(name))) throw new Error("watch_dispatch_unavailable");
		const authority = new WatchRestoreAuthority(actor.storage);
		const fence = new WatchDispatchFence(actor.storage, enrolled);
		let observed: Awaited<ReturnType<typeof readPreference>> = null;
		async function readPreference() {
			const row = await env.DB.prepare(`SELECT pairing.revision, pairing.operation, pairing.body_hash,
				pairing.enabled, pairing.sealed
				FROM watch_lifecycle_preference AS pairing
				JOIN watch_lifecycle_issuer AS issuer
					ON issuer.installation=pairing.installation AND issuer.epoch=pairing.epoch
				WHERE pairing.installation=?1 AND pairing.receiver=?2 AND pairing.incarnation=?3
					AND pairing.epoch=?4 AND issuer.key_fingerprint=?5 AND pairing.retired=0
					AND issuer.scope='watch-lifecycle' AND issuer.active=1`)
				.bind(enrolled.installation, enrolled.receiver, enrolled.incarnation, enrolled.epoch, enrolled.key_fingerprint)
				.first<{revision: number; operation: string | null; body_hash: string | null; enabled: number; sealed: number}>();
			return row;
		}
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
				observed = await readPreference();
				if (!observed) throw new Error("watch_dispatch_unavailable");
				return context.beforeFetch();
			},
		});
	};
}
