import { createSurfaceService, type SurfaceService } from "./composition";
import type { AppEnv } from "../types";

// Source admission only. No environment/configuration/client activation.
const SURFACE_PUSH_HTTP_ENABLED = false as boolean;
let current: SurfaceService | undefined;

/** Reserve the closed issuer prefix before diagnostics, credentials or storage. */
export async function dispatchSurfaceIssuerRequest(request: Request, env: unknown): Promise<Response | undefined> {
    const path = new URL(request.url).pathname;
    if (path !== "/v1/push/surface/issuer" && !path.startsWith("/v1/push/surface/issuer/")) return undefined;
    return dispatchSurfaceRequest(request, env);
}

/** Reserve the entire typed surface namespace before legacy auth/diagnostics. */
export async function dispatchSurfaceRequest(request: Request, env: unknown): Promise<Response | undefined> {
    const path = new URL(request.url).pathname;
    if (path !== "/v1/push/surface" && !path.startsWith("/v1/push/surface/")) return undefined;
    const issuer = path === "/v1/push/surface/issuer" || path.startsWith("/v1/push/surface/issuer/");
    if (!SURFACE_PUSH_HTTP_ENABLED) {
        return new Response(JSON.stringify({ contract_version: 1, success: false, error: issuer ? "surface_issuer_unavailable" : "surface_service_unavailable" }), {
            status: 503,
            headers: {
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        });
    }
    try {
        const candidate = env as AppEnv;
        if (!current?.matches(candidate)) {
            current?.close(); current = undefined;
            let created: SurfaceService;
            created = createSurfaceService({ env: candidate, isCurrent: () => current === created });
            current = created;
        }
        return await current.handle(request, candidate);
    } catch {
        return new Response(JSON.stringify({ contract_version: 1, success: false, error: "surface_service_unavailable" }), {
            status: 503, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
                "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff" },
        });
    }
}
