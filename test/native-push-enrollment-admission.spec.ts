import { env } from "cloudflare:test";
import { beforeAll, expect, it, vi } from "vitest";
import migration from "../migrations/0002_install_tokens.sql?raw";
import { admitNativePushEnrollment, type NativePushChannel, type NativePushScope } from "../src/native-push/enrollment-admission";
import { issueInstallToken } from "../src/repositories/installTokens";

const scope: NativePushScope = {
	installation: "ha-fixture", owner: "owner-fixture", device: "device-fixture",
	pairingGeneration: "pairing-1", channel: "widget", consentGeneration: "consent-1",
	targetDigest: "a".repeat(64), purposeKeyThumbprint: "b".repeat(64),
};
const now = () => 100;
const consent = { scope, choice: "opt_in" as const, expiresAt: 200 };

beforeAll(async () => {
	for (const statement of migration.split(";").filter(part => part.trim())) {
		await env.DB.prepare(statement).run();
	}
});

async function install(installation = scope.installation) {
	const credential = await issueInstallToken(env.DB, { ha_install_id: installation });
	return {
		credential,
		request: new Request("https://api.djconnect.dev/", { headers: { authorization: "Bearer " + credential.token } }),
	};
}

const channels: readonly NativePushChannel[] = ["widget", "live_activity", "moment_app", "watch_smart_stack"];

it.each(channels)("requires explicit %s consent for the exact physical device and generation", async channel => {
	const { request } = await install();
	const selected = { ...scope, channel };
	const original = { ...consent, scope: selected };
	const verifyOriginal = vi.fn(async () => original);
	const authority = { verifyOriginal, isCurrent: async () => true };
	const received = await admitNativePushEnrollment(request, env.DB, selected, authority, now);
	expect(received.consent.scope).toEqual(selected);
	expect(received.installation.ha_install_id).toBe(scope.installation);
	for (const changed of [
		{ device: "second-device" }, { owner: "second-owner" },
		...channels.filter(other => other !== channel).map(other => ({ channel: other })),
		{ consentGeneration: "consent-2" }, { pairingGeneration: "pairing-2" },
		{ targetDigest: "c".repeat(64) }, { purposeKeyThumbprint: "d".repeat(64) },
	]) {
		await expect(admitNativePushEnrollment(request, env.DB, { ...selected, ...changed }, authority, now))
			.rejects.toMatchObject({ status: 403, code: "native_push_consent_required" });
	}
	for (const unavailable of [null, { ...original, choice: "opt_out" as const }]) {
		await expect(admitNativePushEnrollment(request, env.DB, selected,
			{ ...authority, verifyOriginal: async () => unavailable }, now))
			.rejects.toMatchObject({ status: 403 });
	}
});

it("rejects a token from another installation before asking the consent authority", async () => {
	const { request } = await install("foreign-install");
	const verifyOriginal = vi.fn();
	await expect(admitNativePushEnrollment(request, env.DB, scope,
		{ verifyOriginal, isCurrent: async () => true }, now))
		.rejects.toMatchObject({ status: 403, code: "install_token_scope_mismatch" });
	expect(verifyOriginal).not.toHaveBeenCalled();
});

it("rejects retired consent and a token revoked while the consent is checked", async () => {
	const { credential, request } = await install();
	const verifyOriginal = async () => consent;
	await expect(admitNativePushEnrollment(request, env.DB, scope, { verifyOriginal, isCurrent: async () => false }, now))
		.rejects.toMatchObject({ status: 403 });
	await expect(admitNativePushEnrollment(request, env.DB, scope, { verifyOriginal, isCurrent: async () => {
		await env.DB.prepare("UPDATE install_tokens SET disabled = 1 WHERE id = ?").bind(credential.id).run();
		return true;
	} }, now)).rejects.toMatchObject({ status: 401, code: "install_auth_required" });
});
