import { describe, expect, it, vi } from "vitest";
import worker from "../src/index";

const routes = [
	"create", "inspect", "attestation/challenge", "attestation/register", "submit-challenge",
	"submit", "poll", "consume", "cancel", "attestation/delete", "attestation/recover",
];
const responseBody = { v: "djc-rendezvous/1", error: "service_unavailable" };

function poison(): never {
	throw new Error("disabled rendezvous touched a forbidden dependency");
}

async function call(path: string, method = "POST", origin?: string) {
	const request = new Request(`https://api.djconnect.dev${path}`, {
		method,
		headers: { ...(origin === undefined ? {} : { Origin: origin }), Authorization: "Bearer example-sensitive", Cookie: "claim=example-sensitive", "X-Rendezvous-Enabled": "true" },
		...(method === "GET" || method === "HEAD" ? {} : { body: "example-opaque-proof-and-destination" }),
	});
	Object.defineProperties(request, {
		body: { get: poison },
		json: { value: poison },
		text: { value: poison },
		arrayBuffer: { value: poison },
		clone: { value: poison },
	});
	const env = new Proxy({}, { get: poison }) as Env;
	const ctx = new Proxy({}, { get: poison }) as ExecutionContext;
	const output = (["error", "log", "warn", "info", "debug"] as const).map((level) => vi.spyOn(console, level).mockImplementation(poison));
	try {
		const response = await worker.fetch(request, env, ctx);
		expect(request.bodyUsed).toBe(false);
		for (const spy of output) expect(spy).not.toHaveBeenCalled();
		return response;
	} finally {
		for (const spy of output) spy.mockRestore();
	}
}

describe("compiled-disabled product rendezvous perimeter", () => {
	it.each(routes)("isolates %s before body, env, storage, diagnostics or provider work", async (route) => {
		const response = await call(`/v1/rendezvous/${route}`, "POST", "https://vibecast.tv");
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual(responseBody);
	});

	it.each(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])("keeps %s unavailable without successful preflight or replay hints", async (method) => {
		const response = await call("/v1/rendezvous/create", method, "https://vibecast.tv");
		expect(response.status).toBe(503);
		expect(response.headers.get("Access-Control-Allow-Methods")).toBeNull();
		expect(response.headers.get("Access-Control-Allow-Headers")).toBeNull();
		expect(response.headers.get("Access-Control-Allow-Credentials")).toBeNull();
		expect(response.headers.get("Retry-After")).toBeNull();
	});

	it.each([undefined, "null", "https://evil.example", "https://vibecast.tv.evil.example", "http://vibecast.tv", "https://vibecast.tv/", "https://vibecast.tv, https://evil.example"])("does not allow or reflect Origin %s", async (origin) => {
		const response = await call("/v1/rendezvous/create", "POST", origin);
		expect(response.status).toBe(503);
		expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
		expect(await response.json()).toEqual(responseBody);
	});

	it("returns the same private unavailable shape for an exact approved Origin", async () => {
		const response = await call("/v1/rendezvous/unknown/example-sensitive?claim=example-sensitive", "POST", "https://vibecast.tv");
		expect(response.headers.get("Access-Control-Allow-Origin")).toBe("https://vibecast.tv");
		expect(response.headers.get("Cache-Control")).toBe("no-store");
		expect(response.headers.get("Referrer-Policy")).toBe("no-referrer");
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(response.headers.get("Vary")).toBe("Origin");
		expect(await response.json()).toEqual(responseBody);
		expect(JSON.stringify([...response.headers])).not.toContain("example-sensitive");
	});

	it.each(["/v1/rendezvous", "/v1/rendezvous/", "/v1/rendezvous/%2f", "/v1/rendezvous/create?secret=example-sensitive", "/v1/rendezvous/create/"])("reserves the exact namespace or slash descendants: %s", async (path) => {
		expect((await call(path)).status).toBe(503);
	});

	it.each([
		"/v1/rendezvousx/create", "/v1/rendezvous%2Fcreate", "/v1/rendezvous%252Fcreate",
		"/v1/%72endezvous/create", "/v1/Rendezvous/create", "/v2/rendezvous/create",
	])("preserves the root's unknown-route behavior outside the namespace: %s", async (path) => {
		const { response, recorded } = await outside(path);
		expect(response.status).toBe(404);
		expect(await response.json()).toEqual({ error: "not_found" });
		expect(recorded).toHaveLength(1);
		expect(recorded[0].slice(1)).toEqual(["GET", "unmatched", 404, "not_found"]);
	});

	it("keeps health and its existing fixed diagnostic label working", async () => {
		const { response, recorded } = await outside("/health?claim=example-sensitive");
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, service: "djconnect-api" });
		expect(recorded[0].slice(1)).toEqual(["GET", "/health", 200, null]);
		expect(JSON.stringify(recorded)).not.toContain("example-sensitive");
	});
});

async function outside(path: string) {
	const recorded: unknown[][] = [];
	const pending: Promise<unknown>[] = [];
	const db = {
		prepare(sql: string) {
			expect(sql).toContain("INSERT INTO api_diagnostics");
			return {
				bind(...args: unknown[]) {
					recorded.push(args);
					return { run: async () => ({ success: true }) };
				},
			};
		},
	};
	const env = { DB: db } as unknown as Env;
	const ctx = { waitUntil: (work: Promise<unknown>) => pending.push(work) } as unknown as ExecutionContext;
	const response = await worker.fetch(new Request(`https://api.djconnect.dev${path}`), env, ctx);
	await Promise.all(pending);
	return { response, recorded };
}
