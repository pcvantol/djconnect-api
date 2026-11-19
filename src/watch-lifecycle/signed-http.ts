async function readBody(request: Request, signal: AbortSignal) {
	const reader = request.body?.getReader();
	if (!reader) throw new TypeError("missing body");
	const cancel = () => { void reader.cancel().catch(() => undefined); };
	signal.addEventListener("abort", cancel, { once: true });
	const buffer = new Uint8Array(2048);
	let size = 0;
	try {
		for (;;) {
			signal.throwIfAborted();
			const chunk = await reader.read();
			signal.throwIfAborted();
			if (chunk.done) return buffer.slice(0, size);
			if (size + chunk.value.length > buffer.length) throw new TypeError("oversized body");
			buffer.set(chunk.value, size);
			size += chunk.value.length;
		}
	} finally {
		signal.removeEventListener("abort", cancel);
		cancel();
	}
}

/** Read the original body bytes and canonical raw P-256 signature. */
export async function readSignedWatchRequest(request: Request, signal: AbortSignal) {
	const signature = request.headers.get("djc-watch-lifecycle-signature") ?? "";
	if (!/^[A-Za-z0-9_-]{85}[AQgw]$/.test(signature)) throw new TypeError("invalid signature");
	const proof = Uint8Array.from(atob(signature.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
	return { body: await readBody(request, signal), proof };
}
