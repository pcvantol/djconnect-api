/** Product transport boundary only. Enabling the service requires reviewed source. */
export function unavailableRendezvousResponse(request: Request): Response | undefined {
	const path = new URL(request.url).pathname;
	if (path !== "/v1/rendezvous" && !path.startsWith("/v1/rendezvous/")) return undefined;

	const headers = new Headers({
		"Content-Type": "application/json; charset=utf-8",
		"Cache-Control": "no-store",
		"Referrer-Policy": "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"Vary": "Origin",
	});
	if (request.headers.get("Origin") === "https://vibecast.tv") {
		headers.set("Access-Control-Allow-Origin", "https://vibecast.tv");
	}
	return new Response(JSON.stringify({ v: "djc-rendezvous/1", error: "service_unavailable" }), {
		status: 503,
		headers,
	});
}
