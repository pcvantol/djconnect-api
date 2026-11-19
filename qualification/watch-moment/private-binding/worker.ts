import { createOwnedWatchPreference } from "../../../src/watch-lifecycle/owned-preference";
import { WatchRestoreAuthority } from "../../../src/watch-lifecycle/restore-authority";
import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";
import { createWatchPreferenceHttp, type WatchPreferenceAdmission } from "../../../src/watch-lifecycle/preference-http";

import type { WatchMachineContext } from "../../../src/watch-lifecycle/access-ingress";

import { watchDispatchScopeBinding, type WatchDispatchScope } from "../../../src/watch-lifecycle/dispatch-identity";
export { WatchPrivatePreference } from "../../../src/watch-lifecycle/private-entrypoint";

type Scope = Omit<WatchPreferenceAdmission, "action" | "expiresAt" | "submitBeforeMs">;
type LabContext = WatchMachineContext & {
	pauseBeforeLookup?: boolean;
	pauseBeforeBatch?: boolean;
};

interface LabEnv {
	DB: D1Database;
	ACTOR: DurableObjectNamespace<PreferenceActor>;
	PREFERENCE: Service<PrivatePreference>;
}

export class PrivatePreference extends WorkerEntrypoint<LabEnv> {
	preference(context: LabContext, body: Uint8Array<ArrayBuffer>, proof: Uint8Array<ArrayBuffer>) {
		return this.env.ACTOR.getByName("fixture-home:fixture-watch").preference(context, null, body, proof);
	}
}

export class FixturePairing extends WorkerEntrypoint<LabEnv> {
	resolvePreferenceScope(context: WatchMachineContext, receiver: string) {
		return this.env.ACTOR.getByName("fixture-home:fixture-watch").lookup(context, receiver);
	}
}

export class PreferenceActor extends DurableObject<LabEnv> {
	private pause?: () => void;
	private batchCount = 0;
	private loseOwnedReply = false;

	async admit(scope: Scope) {
		this.ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS fixture_admission (id INTEGER PRIMARY KEY, scope TEXT)");
		this.ctx.storage.sql.exec("INSERT INTO fixture_admission VALUES (1, ?)", JSON.stringify(scope));
		new WatchRestoreAuthority(this.ctx.storage).initializeDisabled(scope);
		await this.ctx.storage.sync();
	}

	async revoke() {
		this.ctx.storage.sql.exec("DELETE FROM fixture_admission WHERE id=1");
		await this.ctx.storage.sync();
	}

	loseNextOwnedReply() { this.loseOwnedReply = true; }

	status() {
		return { paused: this.pause !== undefined, batches: this.batchCount };
	}

	resume() {
		this.pause?.();
	}

	lookup(context: WatchMachineContext, receiver: string): WatchDispatchScope | null {
		const entry = this.ctx.storage.sql.exec<{ scope: string }>("SELECT scope FROM fixture_admission WHERE id=1").toArray()[0];
		if (!entry) return null;
		const scope = JSON.parse(entry.scope) as Scope;
		if (scope.installation !== context.installation || scope.receiver !== receiver ||
			scope.credentialId !== context.credentialId || scope.credentialGeneration !== context.credentialGeneration) return null;
		return scope;
	}

	async preference(call: LabContext, resolved: WatchDispatchScope | null, body: Uint8Array<ArrayBuffer>, proof: Uint8Array<ArrayBuffer>) {
		const sql = this.ctx.storage.sql;
		sql.exec("CREATE TABLE IF NOT EXISTS fixture_admission (id INTEGER PRIMARY KEY, scope TEXT)");
		const admitted = () => sql.exec<{ scope: string }>("SELECT scope FROM fixture_admission WHERE id=1").toArray()[0]?.scope;
		const original = admitted();
		if (!original) return new Response(null, { status: 403 });
		const scope = JSON.parse(original) as Scope;
		if (scope.installation !== call.installation || scope.credentialId !== call.credentialId ||
			scope.credentialGeneration !== call.credentialGeneration) return new Response(null, { status: 403 });
		if (resolved && watchDispatchScopeBinding(resolved) !== watchDispatchScopeBinding(scope)) return new Response(null, { status: 403 });
		const signature = btoa(String.fromCharCode(...proof)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
		const db = new Proxy(this.env.DB, {
			get: (target, name, receiver) => {
				if (name === "prepare" && this.loseOwnedReply) {
					return (query: string) => {
						const statement = target.prepare(query);
						if (!query.startsWith("UPDATE watch_lifecycle_preference")) return statement;
						return { bind: (...values: unknown[]) => ({ first: async () => {
							this.loseOwnedReply = false;
							const row = await statement.bind(...values).first();
							this.batchCount++;
							if (!row) throw new Error("fixture CAS did not commit");
							throw new Error("fixture lost CAS acknowledgement");
						} }) };
					};
				}
				if (name === "prepare" && call.pauseBeforeLookup) {
					return (query: string) => {
						const statement = target.prepare(query);
						if (!query.includes("SELECT public_spki_hex")) return statement;
						return { bind: (...values: unknown[]) => ({
							first: async () => {
								const row = await statement.bind(...values).first();
								await this.waitForResume();
								return row;
							},
						}) };
					};
				}
				if (name !== "batch") return Reflect.get(target, name, receiver);
				return async (statements: D1PreparedStatement[]) => {
					if (call.pauseBeforeBatch) await this.waitForResume();
					this.batchCount++;
					return target.batch(statements);
				};
			},
		});
		const assertCurrent = () => {
			if (admitted() !== original) throw new Error("fixture admission withdrawn");
		};
		if (resolved) return createOwnedWatchPreference({
			db, audience: "lab", actor: this.ctx, namespace: this.env.ACTOR,
			assertPairingCurrent: assertCurrent, assertMachineCurrent: assertCurrent,
		})(call, resolved, body, proof);

		// Admission is supplied only by the test harness. Neither RPC nor D1 can install it.
		return createWatchPreferenceHttp(db, "lab", () => {}, {
			...scope, action: call.action, expiresAt: call.expiresAt, submitBeforeMs: call.submitBeforeMs,
		}, assertCurrent)(new Request("https://fixture.invalid/internal", {
			method: "POST", body,
			headers: { "content-type": "application/json", "djc-watch-lifecycle-signature": signature },
		}));
	}

	private async waitForResume() {
		const wait = Promise.withResolvers<void>();
		this.pause = wait.resolve;
		try { await wait.promise; } finally { this.pause = undefined; }
	}
}

export default { fetch: () => new Response(null, { status: 404 }) };
