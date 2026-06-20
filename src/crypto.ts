const encoder = new TextEncoder();

export async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
	return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function base64Url(input: string | ArrayBuffer): string {
	const bytes = typeof input === "string" ? encoder.encode(input) : new Uint8Array(input);
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export async function timingSafeEqualString(left: string, right: string): Promise<boolean> {
	const leftHash = await crypto.subtle.digest("SHA-256", encoder.encode(left));
	const rightHash = await crypto.subtle.digest("SHA-256", encoder.encode(right));
	return crypto.subtle.timingSafeEqual(leftHash, rightHash);
}

export function sanitizeTokenForLog(token: string): string {
	if (token.length <= 12) {
		return "[redacted]";
	}
	return `${token.slice(0, 6)}...${token.slice(-6)}`;
}

export function cryptoRandomId(): string {
	return crypto.randomUUID();
}
