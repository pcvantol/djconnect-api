/** Server composition only; public admission is a separate compiled gate. */
import type { AppEnv } from "../types";
import { createSurfaceIssuer } from "./issuer";
import { createSurfaceEnrollment } from "./enrollment";
import { ENROLLMENT_PREFIX } from "./enrollment-wire";
import { createSurfacePushHandler } from "./handler";
import { createSurfaceProvider, type SurfaceProvider } from "./provider";
import { need } from "./wire";

const fields = ["DB", "APNS_TEAM_ID", "APNS_KEY_ID", "APNS_PRIVATE_KEY", "APNS_TOKEN_ENCRYPTION_KEY",
    "DJCONNECT_RELAY_SECRET", "APNS_ENVIRONMENT", "APNS_TOPIC_IOS", "APNS_TOPIC_MACOS", "APNS_TOPIC_WATCHOS"] as const;
export interface SurfaceServiceOptions {
    env: AppEnv;
    now?: () => number;
    fetcher?: typeof fetch;
    isCurrent?: () => boolean;
}
export interface SurfaceService {
    matches(env: AppEnv): boolean;
    handle(request: Request, env?: AppEnv): Promise<Response>;
    close(): void;
}
export function createSurfaceService(options: SurfaceServiceOptions): SurfaceService {
    const originalEnv = options.env, originalNow = options.now, originalFetch = options.fetcher, originalCurrent = options.isCurrent;
    const env = Object.freeze(Object.fromEntries(fields.map(name => [name, originalEnv[name]]))) as unknown as AppEnv;
    const time = originalNow ?? Date.now, transport = originalFetch ?? fetch;
    let closed = false, highWater = 0, provider: SurfaceProvider | undefined;
    const same = (candidate: AppEnv) => fields.every(name => candidate[name] === env[name]);
    const active = () => {
        let valid = false;
        try { valid = !closed && options.env === originalEnv && options.now === originalNow &&
            options.fetcher === originalFetch && options.isCurrent === originalCurrent &&
            (originalCurrent?.() ?? true) && !closed && same(originalEnv); } catch { valid = false; }
        if (!valid) closed = true; // Once observed retired, this service generation stays retired.
        return valid;
    };
    const guard = (candidate: AppEnv = originalEnv) => {
        need(active() && same(candidate) && active(), "surface_service_unavailable", 503);
    };
    const clock = () => {
        guard(); let value: number;
        try { value = time(); } catch(error) { closed = true; throw error; }
        const qualified = Number.isSafeInteger(value) && value >= highWater && value >= 0;
        if (!qualified) closed = true;
        need(qualified, "surface_clock_unqualified", 503);
        guard(); highWater = value; return value;
    };
    return {
        matches(candidate) { try { return active() && same(candidate) && active(); } catch { return false; } },
        async handle(request, candidate = originalEnv) {
            guard(candidate);
            const now = () => { guard(candidate); return clock(); };
            // One lazy authorizer per immutable service identity. Revocation,
            // status and operator withdrawal never require a usable APNs key.
            const authorizeProvider = async () => {
                guard(candidate);
                provider ??= createSurfaceProvider(env, clock);
                const result = await provider.authorizeProvider();
                guard(candidate); return result;
            };
            const fetcher: typeof fetch = async (input, init) => {
                guard(candidate);
                const response = await transport(input, init);
                guard(candidate); return response;
            };
            const path = new URL(request.url).pathname;
            const issuer = path === "/v1/push/surface/issuer" || path.startsWith("/v1/push/surface/issuer/");
            const enrollment = path === ENROLLMENT_PREFIX.slice(0, -1) || path.startsWith(ENROLLMENT_PREFIX);
            const handler = enrollment ? createSurfaceEnrollment({ env, now,
                isCurrent: () => { guard(candidate); return true; } }) :
                issuer ? createSurfaceIssuer({ env, now, admittedProfiles: [] }) :
                createSurfacePushHandler({ db: env.DB, encryptionKey: env.APNS_TOKEN_ENCRYPTION_KEY,
                    authorizeProvider, fetcher, now, activityProfiles: [] });
            const response = await handler(request);
            guard(candidate); return response;
        },
        close() { closed = true; provider?.close(); provider = undefined; },
    };
}
