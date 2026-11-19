import { WorkerEntrypoint } from "cloudflare:workers";
import type { WatchMachineContext } from "./access-ingress";
import { watchDispatchScopeBinding, watchRestoreActorName, type WatchDispatchScope } from "./dispatch-identity";
import { decodeLifecycleClaims } from "./proof";

interface PreferenceActorBinding {
	preference(context: WatchMachineContext, scope: WatchDispatchScope,
		body: Uint8Array<ArrayBuffer>, proof: Uint8Array<ArrayBuffer>): Promise<Response>;
}

interface WatchPrivateBindings {
	WATCH_LIFECYCLE_AUDIENCE?: string;
	WATCH_PAIRING_AUTHORITY?: {
		/** The receiver is a lookup hint; the authority must independently admit the current pairing. */
		resolvePreferenceScope(context: WatchMachineContext, receiver: string): Promise<WatchDispatchScope | null>;
	};
	WATCH_PREFERENCE_ACTOR?: Pick<DurableObjectNamespace, "idFromName"> & {
		get(id: DurableObjectId): PreferenceActorBinding;
	};
}

const headers = { "cache-control": "no-store", "x-content-type-options": "nosniff" };
const unavailable = () => Response.json({ error: "watch_preference_unavailable" }, { status: 403, headers });

/** Named RPC entrypoint only. Authority bindings must be supplied by an admitted deployment. */
export class WatchPrivatePreference extends WorkerEntrypoint<WatchPrivateBindings> {
	async preference(input: WatchMachineContext, bytes: Uint8Array, signature: Uint8Array): Promise<Response> {
		const { WATCH_LIFECYCLE_AUDIENCE: audience, WATCH_PAIRING_AUTHORITY: pairing, WATCH_PREFERENCE_ACTOR: actors } = this.env;
		if (!audience || !pairing || !actors || !(bytes instanceof Uint8Array) || bytes.length > 2048 ||
			!(signature instanceof Uint8Array) || signature.length !== 64) return unavailable();
		let writeForwarded = false;
		try {
			const context = Object.freeze({
				installation: input.installation,
				credentialId: input.credentialId,
				credentialGeneration: input.credentialGeneration,
				action: input.action,
				expiresAt: input.expiresAt,
				submitBeforeMs: input.submitBeforeMs,
			});
			const current = () => Number.isSafeInteger(context.submitBeforeMs) && Date.now() < context.submitBeforeMs &&
				Number.isSafeInteger(context.expiresAt) && Math.floor(Date.now() / 1000) < context.expiresAt;
			if (!current() || !context.credentialId || !Number.isSafeInteger(context.credentialGeneration) ||
				context.credentialGeneration < 1 ||
				(context.action !== "preference-read" && context.action !== "preference-write")) return unavailable();

			const body = new Uint8Array(bytes);
			const proof = new Uint8Array(signature);
			const claims = decodeLifecycleClaims(body, audience, Math.floor(Date.now() / 1000));
			if (claims.installation !== context.installation || claims.action !== context.action) return unavailable();
			const resolved = await pairing.resolvePreferenceScope(context, claims.receiver);
			if (!resolved) return unavailable();
			const scope = Object.freeze({
				installation: resolved.installation,
				receiver: resolved.receiver,
				incarnation: resolved.incarnation,
				epoch: resolved.epoch,
				key_fingerprint: resolved.key_fingerprint,
			});
			const expected = watchDispatchScopeBinding(claims);
			if (expected === null || expected !== watchDispatchScopeBinding(scope)) return unavailable();
			const name = await watchRestoreActorName(scope);
			if (!name || !current() || claims.expiry <= Math.floor(Date.now() / 1000)) return unavailable();
			const actor = actors.get(actors.idFromName(name));
			writeForwarded = context.action === "preference-write";
			const response = await actor.preference(context, scope, body, proof);
			if (!current() || claims.expiry <= Math.floor(Date.now() / 1000)) throw new Error("Watch private admission expired");
			return response;
		} catch {
			return writeForwarded
				? Response.json({ error: "watch_preference_outcome_unknown" }, { status: 503, headers })
				: unavailable();
		}
	}
}

export default { fetch: () => new Response(null, { status: 404 }) };
