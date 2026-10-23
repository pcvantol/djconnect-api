import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { dispatchSurfaceIssuerRequest } from "../src/surface-push/dispatch";

const forbidden = new Proxy({}, { get() { throw new Error("closed issuer accessed authority or diagnostics"); } });

describe("compiled closed issuer HTTP boundary", () => {
    for (const action of ["", "/operator/enrol", "/operator/withdraw", "/challenge", "/issue", "/status", "/withdraw", "/unknown"]) {
        for (const method of ["GET", "POST", "OPTIONS"]) {
            it(`${method} ${action || "root"} is closed before body/env/diagnostics`, async () => {
                const original = new Request(`https://example.invalid/v1/push/surface/issuer${action}`, { method });
                const request = new Proxy(original, { get(target, key) {
                    if (key !== "url") throw new Error("closed issuer inspected body, headers or credentials");
                    return target.url;
                }});
                const reply = await worker.fetch(request as Parameters<typeof worker.fetch>[0], forbidden as Env, forbidden as ExecutionContext);
                expect(reply.status).toBe(503);
                expect(reply.headers.get("Cache-Control")).toBe("no-store");
                expect(reply.headers.get("Referrer-Policy")).toBe("no-referrer");
                expect(reply.headers.get("Access-Control-Allow-Origin")).toBeNull();
                expect(await reply.json()).toEqual({ contract_version: 1, success: false, error: "surface_issuer_unavailable" });
            });
        }
    }
    it("does not claim other ordinary push or rendezvous paths", async () => {
        for (const path of ["/", "/v1/push/event", "/v1/push/surface/register", "/v1/rendezvous", "/v1/push/surface/issuer-other"]) {
            expect(await dispatchSurfaceIssuerRequest(new Request(`https://example.invalid${path}`), forbidden)).toBeUndefined();
        }
    });
});
