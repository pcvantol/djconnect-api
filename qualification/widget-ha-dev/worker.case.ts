import { createExecutionContext, env } from "cloudflare:test";
import { expect, it, vi } from "vitest";
import worker, { WidgetEnrollmentOperator } from "../../src/surface-push/widget-ha-dev-worker";

const origin = "https://widget.fixture.invalid";
const operatorOrigin = "https://widget-enrollment.internal";
const prefix = "/v1/push/surface/";
const operatorSecret = "local-enrollment-fixture";
const local = env as unknown as { WIDGET_HA_DEV_DB: D1Database; WIDGET_PILOT_MODE: string };
const fixture = () => ({
	WIDGET_WORKER_VERSION: { id: crypto.randomUUID(), tag: "fixture", timestamp: "fixture" },
	WIDGET_PILOT_MODE: "transport-v1",
	WIDGET_PILOT_ORIGIN: origin,
	WIDGET_ACCESS_ISSUER: "https://widget-fixture.cloudflareaccess.com",
	WIDGET_ACCESS_AUDIENCE: "fixture-audience",
	WIDGET_ACCESS_CLIENT_ID: "fixture.access",
	WIDGET_ACCESS_GENERATION: "1",
	WIDGET_PILOT_EXPIRES_AT_MS: String(Date.now() + 30_000),
	WIDGET_HA_DEV_DB: local.WIDGET_HA_DEV_DB,
	WIDGET_TOKEN_ENCRYPTION_KEY: btoa("0123456789abcdef0123456789abcdef"),
	WIDGET_ENROLLMENT_OPERATOR_SECRET: operatorSecret,
});

function post(path: string, host = origin, bearer?: string) {
	const headers = new Headers({ "content-type": "application/json" });
	if (bearer) headers.set("authorization", "Bearer " + bearer);
	return new Request(host + prefix + path, { method: "POST", headers, body: "{}" });
}

it("binds only local WidgetKit D1 and closes by default", async () => {
	const config = fixture();
	expect(await config.WIDGET_HA_DEV_DB.prepare("SELECT 1 AS probe").first("probe")).toBe(1);
	expect(Object.keys(local).filter(key => !key.startsWith("__VITEST_POOL_WORKERS_")).sort()).toEqual(["WIDGET_HA_DEV_DB", "WIDGET_PILOT_MODE", "WIDGET_WORKER_VERSION"]);
	const ctx = createExecutionContext();
	expect((await worker.fetch(post("status"), local, ctx)).status).toBe(503);
	expect((await worker.fetch(post("status"), { ...config, WIDGET_PILOT_EXPIRES_AT_MS: "1" }, ctx)).status).toBe(503);
});

it("denies public management, missing machine admission and the APNs event route", async () => {
	const config = fixture();
	const ctx = createExecutionContext();
	expect((await worker.fetch(post("enrollment/operator/authorize", origin, operatorSecret), config, ctx)).status).toBe(404);
	expect((await worker.fetch(post("status"), config, ctx)).status).toBe(403);
	expect((await worker.fetch(post("event"), config, ctx)).status).toBe(404);
});

it("exposes only authorize and revoke through the named operator with existing proof", async () => {
	const ctx = createExecutionContext();
	const operator = new WidgetEnrollmentOperator(ctx, fixture());
	expect((await operator.fetch(post("enrollment/redeem", operatorOrigin, operatorSecret))).status).toBe(404);
	for (const action of ["authorize", "revoke"]) {
		const path = "enrollment/operator/" + action;
		expect((await operator.fetch(post(path, origin, operatorSecret))).status).toBe(404);
		expect((await operator.fetch(post(path, operatorOrigin))).status).toBe(401);
		expect((await operator.fetch(post(path, operatorOrigin, operatorSecret))).status).toBe(400);
	}
});

it.each(["public", "operator"] as const)("latches a shared D1 replacement detected by %s", async first => {
	const config = fixture();
	const ctx = createExecutionContext();
	const operator = new WidgetEnrollmentOperator(ctx, config);
	const publicStatus = () => worker.fetch(post("status"), config, ctx);
	const operationId = Date.now().toString(16).padStart(12, "0").replace(/^(.{8})(.{4})$/, "$1-$2") +
		"-7000-8000-000000000001";
	const operatorRequest = (bearer?: string) => operator.fetch(new Request(
		operatorOrigin + prefix + "enrollment/operator/revoke", {
			method: "POST",
			headers: { "content-type": "application/json", ...(bearer ? { authorization: "Bearer " + bearer } : {}) },
			body: JSON.stringify({ contract_version: 1, purpose: "surface_enrollment", action: "revoke",
				operation_id: operationId, authorization_id: "pilot-fixture" }),
		}));
	expect((await publicStatus()).status).toBe(403);
	expect((await operatorRequest()).status).toBe(401);
	const prepare = vi.fn(() => { throw new Error("Replacement D1 must not be accessed"); });
	config.WIDGET_HA_DEV_DB = { prepare } as unknown as D1Database;
	if (first === "public") expect((await publicStatus()).status).toBe(503);
	else expect((await operatorRequest(operatorSecret)).status).toBe(503);
	expect((await operatorRequest(operatorSecret)).status).toBe(503);
	expect((await publicStatus()).status).toBe(503);
	config.WIDGET_HA_DEV_DB = local.WIDGET_HA_DEV_DB;
	expect((await publicStatus()).status).toBe(503);
	expect((await operatorRequest(operatorSecret)).status).toBe(503);
	expect(prepare).not.toHaveBeenCalled();
	// A different env wrapper does not reset a retired version.
	expect((await worker.fetch(post("status"), { ...config }, ctx)).status).toBe(503);
	// A new immutable Worker version has its own captured composition.
	expect((await worker.fetch(post("status"), fixture(), ctx)).status).toBe(403);
});
