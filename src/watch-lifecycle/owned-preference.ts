import type { WatchMachineContext } from "./access-ingress";
import { watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import { createWatchPreferenceHttp, type WatchPreferenceAdmission } from "./preference-http";
import type { LifecycleClaims } from "./proof";
import { WatchRestoreAuthority } from "./restore-authority";

interface WatchPreferenceOwner {
	db: D1Database;
	audience: string;
	actor: DurableObjectState;
	namespace: Pick<DurableObjectNamespace, "idFromName">;
	assertPairingCurrent(claims: LifecycleClaims): void;
	assertMachineCurrent(admission: WatchPreferenceAdmission): void;
}

const unavailable = () => Response.json({ error: "watch_preference_unavailable" }, {
	status: 403, headers: { "cache-control": "no-store" },
});

/** Compose only inside the independently admitted stable owner. */
export function createOwnedWatchPreference(owner?: WatchPreferenceOwner) {
	return async (context: WatchMachineContext, scope: WatchDispatchScope,
		body: Uint8Array<ArrayBuffer>, proof: Uint8Array<ArrayBuffer>): Promise<Response> => {
		if (!owner || !owner.audience || typeof owner.assertPairingCurrent !== "function" ||
			typeof owner.assertMachineCurrent !== "function" || context.installation !== scope.installation ||
			body.length > 2048 || proof.length !== 64) return unavailable();
		const admission = Object.freeze({
			installation: scope.installation, receiver: scope.receiver, incarnation: scope.incarnation,
			epoch: scope.epoch, key_fingerprint: scope.key_fingerprint, action: context.action,
			expiresAt: context.expiresAt, submitBeforeMs: context.submitBeforeMs,
			credentialId: context.credentialId, credentialGeneration: context.credentialGeneration,
		});
		const request = new Request("https://watch-owner.invalid/preference", {
			method: "POST", body,
			headers: {
				"content-type": "application/json",
				"djc-watch-lifecycle-signature": btoa(String.fromCharCode(...proof))
					.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
			},
		});
		const name = await watchRestoreActorName(admission);
		if (!name || !owner.actor.id.equals(owner.namespace.idFromName(name))) return unavailable();
		const restore = new WatchRestoreAuthority(owner.actor.storage);
		return createWatchPreferenceHttp(owner.db, owner.audience, owner.assertPairingCurrent,
			admission, owner.assertMachineCurrent, restore)(request);
	};
}
