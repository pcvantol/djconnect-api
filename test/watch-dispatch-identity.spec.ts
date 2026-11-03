import { expect, it } from "vitest";
import { watchDispatchActorName } from "../src/watch-lifecycle/dispatch-identity";

it("addresses the same actor only for the exact enrolled Watch scope", async () => {
	const scope = { installation: "home", receiver: "watch", incarnation: "pair-a",
		epoch: 1, key_fingerprint: "a".repeat(64) };
	const original = await watchDispatchActorName(scope);
	expect(original).toMatch(/^[a-f0-9]{64}$/);
	expect(await watchDispatchActorName({ ...scope })).toBe(original);
	const alternatives = await Promise.all([
		{ installation: "other-home" }, { receiver: "other-watch" }, { incarnation: "pair-b" },
		{ epoch: 2 }, { key_fingerprint: "b".repeat(64) },
	].map(update => watchDispatchActorName({ ...scope, ...update })));
	expect(new Set([original, ...alternatives]).size).toBe(6);
	expect(alternatives.every(name => /^[a-f0-9]{64}$/.test(name ?? ""))).toBe(true);
	expect(await watchDispatchActorName({ ...scope, epoch: 0 })).toBeNull();
	expect(await watchDispatchActorName({ ...scope, incarnation: "pair a" })).toBeNull();
});
