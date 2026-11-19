import { env } from "cloudflare:test";
import { beforeAll, expect, it } from "vitest";
import installMigration from "../migrations/0002_install_tokens.sql?raw";
import { createWidgetWireTrial, schema, widgetStatement } from "../qualification/native-push-mvp/widget-wire";
import { base64Url } from "../src/crypto";
import { issueInstallToken, rotateInstallToken } from "../src/repositories/installTokens";

beforeAll(async () => {
	for (const statement of [...installMigration.split(";").filter(part => part.trim()), ...schema]) {
		await env.DB.prepare(statement).run();
	}
});

const es256 = { name: "ECDSA", hash: "SHA-256" };
async function fixture() {
	const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
	const foreignKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
	const fixtureId = crypto.randomUUID();
	const installation = `installation-${fixtureId}`;
	const install = await issueInstallToken(env.DB, { ha_install_id: installation });
	const foreignInstall = await issueInstallToken(env.DB, { ha_install_id: `foreign-${fixtureId}` });
	const first = { installation, pair: `pair-1-${fixtureId}`, device: "device-1", appKey: "app-1", target: "widget-1" };
	const second = { ...first, pair: `pair-2-${fixtureId}`, device: "device-2", appKey: "app-2", target: "widget-2" };
	let currentnessHook: (() => Promise<void>) | undefined;
	const pairing = (scope: typeof first) => ({ scope, isCurrent: async () => {
		await currentnessHook?.();
		return true;
	} });
	let wall = Date.now();
	let afterProof: (() => Promise<void>) | undefined;
	const trial = createWidgetWireTrial({
		db: env.DB, now: () => wall,
		capturePair: async scope => scope.pair === first.pair ? pairing(first) : scope.pair === second.pair ? pairing(second) : null,
		async verifyHostProof(input, proof, pair) {
			const hostKey = pair.scope.appKey === first.appKey ? key.publicKey : foreignKey.publicKey;
			const valid = await crypto.subtle.verify(es256, hostKey, new Uint8Array(proof), new Uint8Array(input));
			await afterProof?.();
			return valid;
		},
	});
	const sign = async (action: Parameters<typeof widgetStatement>[0], challenge: Parameters<typeof widgetStatement>[1],
		signer = key.privateKey) => base64Url(await crypto.subtle.sign(es256, signer, widgetStatement(action, challenge)));
	const state = (id: string) => env.DB.prepare("SELECT state FROM trial_widget_challenge WHERE id = ?").bind(id).first("state");
	const count = () => env.DB.prepare("SELECT COUNT(*) AS count FROM trial_widget_challenge WHERE installation = ?")
		.bind(installation).first("count");
	return { trial, sign, state, count, first, second, pairing, install, foreignInstall, foreignKey,
		onCurrentness(hook: typeof currentnessHook) { currentnessHook = hook; },
		expire() { wall += 60_001; }, afterProof(hook: () => Promise<void>) { afterProof = hook; } };
}

it("starts off and never treats pairing, a challenge, or a different signed action as consent", async () => {
	const f = await fixture();
	expect(await f.count()).toBe(0);
	await expect(f.trial.challenge(f.install.token, { ...f.first, pair: "not-committed" }))
		.rejects.toMatchObject({ status: 403 });
	expect(await f.count()).toBe(0);
	const pending = await f.trial.challenge(f.install.token, f.first);
	await expect(f.trial.optIn(f.install.token, pending, await f.sign("opt_out", pending)))
		.rejects.toMatchObject({ status: 403 });
	expect(await f.state(pending.id)).toBe("pending");
});

it("enables one widget only after signed opt-in and keeps opt-out and unlink scoped", async () => {
	const f = await fixture();
	const first = await f.trial.challenge(f.install.token, f.first);
	const second = await f.trial.challenge(f.install.token, f.second);
	expect(await f.state(first.id)).toBe("pending");
	const firstProof = await f.sign("opt_in", first);
	const race = await Promise.allSettled([
		f.trial.optIn(f.install.token, first, firstProof), f.trial.optIn(f.install.token, first, firstProof),
	]);
	expect(race.map(result => result.status).sort()).toEqual(["fulfilled", "rejected"]);
	await f.trial.optIn(f.install.token, second, await f.sign("opt_in", second, f.foreignKey.privateKey));
	await expect(f.trial.optOut(f.install.token, first, firstProof)).rejects.toMatchObject({ status: 403 });
	const late = await f.trial.challenge(f.install.token, f.first);
	const lateProof = await f.sign("opt_in", late);
	await expect(f.trial.optIn(f.install.token, late, lateProof)).rejects.toMatchObject({ status: 409 });
	await f.trial.optOut(f.install.token, first, await f.sign("opt_out", first));
	expect(await f.state(late.id)).toBe("revoked");
	await expect(f.trial.optIn(f.install.token, late, lateProof)).rejects.toMatchObject({ status: 409 });
	expect(await f.state(first.id)).toBe("revoked");
	expect(await f.state(second.id)).toBe("active");
	const pending = await f.trial.challenge(f.install.token, f.second);
	await f.trial.unlink(f.pairing(f.second));
	expect(await f.state(second.id)).toBe("revoked");
	await expect(f.trial.optIn(f.install.token, pending, await f.sign("opt_in", pending, f.foreignKey.privateKey)))
		.rejects.toMatchObject({ status: 409 });
	await expect(f.trial.challenge(f.install.token, f.second)).rejects.toMatchObject({ status: 403 });
});

it("denies wrong installation, app, pairing or target and an expired original challenge", async () => {
	const f = await fixture();
	const challenge = await f.trial.challenge(f.install.token, f.first);
	const proof = await f.sign("opt_in", challenge);
	await expect(f.trial.challenge(f.foreignInstall.token, f.first)).rejects.toMatchObject({ status: 403 });
	await expect(f.trial.optIn(f.foreignInstall.token, challenge, proof)).rejects.toMatchObject({ status: 403 });
	await expect(f.trial.optIn(f.install.token, challenge, await f.sign("opt_in", challenge, f.foreignKey.privateKey)))
		.rejects.toMatchObject({ status: 403 });
	for (const changed of [{ pair: f.second.pair }, { target: f.second.target }]) {
		const swapped = { ...challenge, ...changed };
		await expect(f.trial.optIn(f.install.token, swapped, await f.sign("opt_in", swapped))).rejects.toMatchObject({ status: 403 });
	}
	const second = await f.trial.challenge(f.install.token, f.second);
	const crossed = { ...second, id: challenge.id, nonce: challenge.nonce };
	await expect(f.trial.optIn(f.install.token, crossed, await f.sign("opt_in", crossed, f.foreignKey.privateKey)))
		.rejects.toMatchObject({ status: 403 });
	expect(await f.state(second.id)).toBe("pending");
	f.expire();
	await expect(f.trial.optIn(f.install.token, challenge, proof)).rejects.toMatchObject({ status: 409 });
	expect(await f.state(challenge.id)).toBe("pending");
});

it("rejects both old and new credentials for an original challenge after rotation during proof", async () => {
	const f = await fixture();
	const challenge = await f.trial.challenge(f.install.token, f.first);
	let replacement: Awaited<ReturnType<typeof rotateInstallToken>> | undefined;
	f.afterProof(async () => {
		replacement = await rotateInstallToken(env.DB, { ha_install_id: f.first.installation });
	});
	await expect(f.trial.optIn(f.install.token, challenge, await f.sign("opt_in", challenge)))
		.rejects.toMatchObject({ status: 409 });
	if (!replacement) throw new Error("credential rotation did not run");
	expect(replacement.id).not.toBe(f.install.id);
	const replaced = { ...challenge, credentialId: replacement.id };
	await expect(f.trial.optIn(replacement.token, replaced, await f.sign("opt_in", replaced)))
		.rejects.toMatchObject({ status: 403 });
	expect(await f.state(challenge.id)).toBe("pending");
});

it("does not let a retired opt-out witness revoke a fresh explicit opt-in", async () => {
	const f = await fixture();
	const pending = await f.trial.challenge(f.install.token, f.first);
	const original = await f.trial.challenge(f.install.token, f.first);
	await f.trial.optIn(f.install.token, original, await f.sign("opt_in", original));
	const withdraw = await f.sign("opt_out", pending);
	await f.trial.optOut(f.install.token, pending, withdraw);
	expect(await f.state(original.id)).toBe("revoked");
	const fresh = await f.trial.challenge(f.install.token, f.first);
	await f.trial.optIn(f.install.token, fresh, await f.sign("opt_in", fresh));
	await expect(f.trial.optOut(f.install.token, pending, withdraw)).rejects.toMatchObject({ status: 409 });
	expect(await f.state(fresh.id)).toBe("active");
});

it.each(["opt-out", "unlink"] as const)("fences first opt-in when %s commits before the activation write", async (action) => {
	const f = await fixture();
	const first = await f.trial.challenge(f.install.token, f.first);
	const second = await f.trial.challenge(f.install.token, f.second);
	await f.trial.optIn(f.install.token, second, await f.sign("opt_in", second, f.foreignKey.privateKey));
	const revoke = await f.sign("opt_out", first);
	f.afterProof(async () => {
		f.onCurrentness(async () => {
			// Return the positive snapshot from before retirement. The D1 write must still refuse.
			f.onCurrentness(undefined);
			f.afterProof(async () => {});
			if (action === "opt-out") await f.trial.optOut(f.install.token, first, revoke);
			else await f.trial.unlink(f.pairing(f.first));
		});
	});
	const proof = await f.sign("opt_in", first);
	await expect(f.trial.optIn(f.install.token, first, proof)).rejects.toMatchObject({ status: 409 });
	expect(await f.state(first.id)).toBe("revoked");
	expect(await f.state(second.id)).toBe("active");
	await expect(f.trial.optIn(f.install.token, first, proof)).rejects.toMatchObject({ status: 409 });
});
