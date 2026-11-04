import { createWatchAccessIngress } from "./access-ingress";

const endpoint = "https://watch-ha-dev.djconnect.dev/v1/watch/preference";

interface HaDevBindings {
	WATCH_ACCESS_ISSUER?: string;
	WATCH_ACCESS_AUDIENCE?: string;
	WATCH_LIFECYCLE_AUDIENCE?: string;
	WATCH_INSTALLATION?: string;
	WATCH_ACCESS_CLIENT_ID?: string;
	WATCH_ACCESS_GENERATION?: string;
	WATCH_ACCESS_MAX_AGE_SECONDS?: string;
	WATCH_PRIVATE_PREFERENCE?: Parameters<typeof createWatchAccessIngress>[1];
}

const closed = createWatchAccessIngress();

/** Dedicated HA-dev Worker entrypoint. It is not exported by the public API. */
export default {
	fetch(request, env, ctx): Promise<Response> {
		const {
			WATCH_ACCESS_ISSUER: issuer, WATCH_ACCESS_AUDIENCE: accessAudience,
			WATCH_LIFECYCLE_AUDIENCE: lifecycleAudience, WATCH_INSTALLATION: installation,
			WATCH_ACCESS_CLIENT_ID: credentialId, WATCH_ACCESS_GENERATION: generation,
			WATCH_ACCESS_MAX_AGE_SECONDS: maxAge, WATCH_PRIVATE_PREFERENCE: binding,
		} = env;
		if (!issuer || !accessAudience || !lifecycleAudience || !installation || !credentialId ||
			!generation || !/^[1-9][0-9]*$/.test(generation) || !maxAge || !/^[1-9][0-9]?$/.test(maxAge) ||
			Number(maxAge) > 30 || !binding || typeof binding.preference !== "function") return closed(request, ctx);
		return createWatchAccessIngress({
			endpoint, issuer, accessAudience, lifecycleAudience, installation, credentialId,
			credentialGeneration: Number(generation), maxAssertionAgeSeconds: Number(maxAge),
		}, binding)(request, ctx);
	},
} satisfies ExportedHandler<HaDevBindings>;
