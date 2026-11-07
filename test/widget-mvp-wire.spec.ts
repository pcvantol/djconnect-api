import { env } from "cloudflare:test";
import { beforeAll, expect, it } from "vitest";
import installMigration from "../migrations/0002_install_tokens.sql?raw";
import { createWidgetWireTrial, schema, widgetStatement } from "../qualification/native-push-mvp/widget-wire";
import { base64Url } from "../src/crypto";
import { issueInstallToken } from "../src/repositories/installTokens";

beforeAll(async () => {
	for (const statement of [...installMigration.split(";").filter(part => part.trim()), ...schema]) {
		await env.DB.prepare(statement).run();
	}
});

const es256 = { name: "ECDSA", hash: "SHA-256" };
async function fixture() {
	const key = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
	const foreignKey = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
	const install = await issueInstallToken(env.DB, { ha_install_id: "installation-1" });
	const foreignInstall = await issueInstallToken(env.DB, { ha_install_id: "installation-2" });
	const first = { installation: "installation-1", pair: "pair-1", device: "device-1", appKey: "app-1", target: "widget-1" };
	const second = { ...first, pair: "pair-2", device: "device-2", appKey: "app-2", target: "widget-2" };
	const pairing = (scope: typeof first) => ({ scope, isCurrent: async () => true });
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
	return { trial, sign, state, first, second, pairing, install, foreignInstall, foreignKey,
		expire() { wall += 60_001; }, afterProof(hook: () => Promise<void>) { afterProof = hook; } };
}

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
	f.expire();
	await expect(f.trial.optIn(f.install.token, challenge, proof)).rejects.toMatchObject({ status: 409 });
	expect(await f.state(challenge.id)).toBe("pending");
});

it("checks the original installation credential inside the activation write", async () => {
	const f = await fixture();
	const challenge = await f.trial.challenge(f.install.token, f.first);
	f.afterProof(async () => {
		await env.DB.prepare("UPDATE install_tokens SET disabled = 1 WHERE id = ?").bind(f.install.id).run();
	});
	await expect(f.trial.optIn(f.install.token, challenge, await f.sign("opt_in", challenge)))
		.rejects.toMatchObject({ status: 409 });
	expect(await f.state(challenge.id)).toBe("pending");
});
