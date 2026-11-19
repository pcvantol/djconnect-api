const encoder = new TextEncoder();
const decoder = new TextDecoder();

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

export function base64Encode(input: ArrayBuffer | Uint8Array): string {
	const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

export function base64Decode(value: string): Uint8Array {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}
	return bytes;
}

export async function encryptSecret(plaintext: string, base64Key: string): Promise<{ ciphertext: string; nonce: string; keyVersion: string }> {
	const nonce = new Uint8Array(12);
	crypto.getRandomValues(nonce);
	const key = await importAesGcmKey(base64Key);
	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: nonce },
		key,
		encoder.encode(plaintext),
	);
	return {
		ciphertext: base64Encode(ciphertext),
		nonce: base64Encode(nonce),
		keyVersion: await encryptionKeyVersion(base64Key),
	};
}

export async function decryptSecret(ciphertext: string, nonce: string, base64Key: string): Promise<string> {
	const key = await importAesGcmKey(base64Key);
	const plaintext = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: base64Decode(nonce) },
		key,
		base64Decode(ciphertext),
	);
	return decoder.decode(plaintext);
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

export function cryptoRandomToken(prefix: string): string {
	const bytes = new Uint8Array(32);
	crypto.getRandomValues(bytes);
	return `${prefix}_${base64Url(bytes.buffer)}`;
}

async function importAesGcmKey(base64Key: string): Promise<CryptoKey> {
	const keyBytes = base64Decode(base64Key.trim());
	if (keyBytes.byteLength !== 32) {
		throw new Error("invalid_encryption_key");
	}
	return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptionKeyVersion(base64Key: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", base64Decode(base64Key.trim()));
	return base64Url(digest).slice(0, 16);
}
