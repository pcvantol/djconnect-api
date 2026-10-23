import { createSurfaceIssuer } from "./issuer";
import type { AppEnv } from "../types";

// Source admission only. No environment/configuration/client activation.
const SURFACE_ISSUER_HTTP_ENABLED = false as boolean;

/** Reserve the closed issuer prefix before diagnostics, credentials or storage. */
export async function dispatchSurfaceIssuerRequest(request: Request, env: unknown): Promise<Response | undefined> {
    const path = new URL(request.url).pathname;
    if (path !== "/v1/push/surface/issuer" && !path.startsWith("/v1/push/surface/issuer/")) return undefined;
    if (!SURFACE_ISSUER_HTTP_ENABLED) {
        return new Response(JSON.stringify({ contract_version: 1, success: false, error: "surface_issuer_unavailable" }), {
            status: 503,
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        });
    }
    return createSurfaceIssuer({ env: env as AppEnv })(request);
}
