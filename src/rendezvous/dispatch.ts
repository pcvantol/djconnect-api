import { createProductRendezvousHandler, type ProductRendezvousEnv } from "./composition";
import { unavailableRendezvousResponse } from "./perimeter";

// Activation requires a separately reviewed source change, never configuration.
const PRODUCT_RENDEZVOUS_ENABLED = false as boolean;

/** Reserve rendezvous before the existing API touches credentials or storage. */
export async function dispatchRendezvousRequest(request: Request, env: unknown): Promise<Response | undefined> {
	const unavailable = unavailableRendezvousResponse(request);
	if (!unavailable || !PRODUCT_RENDEZVOUS_ENABLED) return unavailable;
	return createProductRendezvousHandler(env as ProductRendezvousEnv)(request);
}
