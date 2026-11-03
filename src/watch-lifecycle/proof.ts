import { parseStrictJson } from "../surface-push/wire";

const domain = new TextEncoder().encode("DJC-WATCH-LIFECYCLE-V1\0");
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const identifier = /^[A-Za-z0-9._~-]{1,160}$/;
const hexDigest = /^[a-f0-9]{64}$/;
const common = ["audience", "action", "installation", "receiver", "epoch", "key_fingerprint", "expiry", "operation", "incarnation"];
const actionFields = {
	pair: [],
	replace: ["predecessor"],
	retire: [],
	"preference-write": ["expected_version", "enabled"],
	"preference-read": [],
} as const;

export type LifecycleClaims = Readonly<{
	audience: string; action: keyof typeof actionFields; installation: string; receiver: string;
	epoch: number; key_fingerprint: string; expiry: number; operation: string; incarnation: string;
	predecessor?: string; expected_version?: number; enabled?: boolean;
}>;

function isCounter(value: unknown): value is number {
	return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
}

async function digest(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
		byte => byte.toString(16).padStart(2, "0")).join("");
}

function decode(body: Uint8Array, expectedAudience: string, now: number): LifecycleClaims {
	if (!body.length || body.length > 2048) throw new TypeError("invalid lifecycle body");
	const value = parseStrictJson(decoder.decode(body)) as Record<string, unknown> | null;
	if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.action !== "string"
		|| !Object.hasOwn(actionFields, value.action)) throw new TypeError("invalid lifecycle action");
	const fields = [...common, ...actionFields[value.action as keyof typeof actionFields]];
	if (Object.keys(value).length !== fields.length || !fields.every(field => Object.hasOwn(value, field))
		|| value.audience !== expectedAudience || !isCounter(now) || !isCounter(value.expiry)
		|| value.expiry <= now || value.expiry - now > 30 || !isCounter(value.epoch)
		|| typeof value.key_fingerprint !== "string" || !hexDigest.test(value.key_fingerprint)) {
		throw new TypeError("invalid lifecycle claims");
	}
	for (const name of ["installation", "receiver", "operation", "incarnation", ...(value.action === "replace" ? ["predecessor"] : [])]) {
		const id = value[name];
		if (typeof id !== "string" || !identifier.test(id)) throw new TypeError("invalid lifecycle identifier");
	}
	if (value.action === "preference-write" && (!isCounter(value.expected_version) || typeof value.enabled !== "boolean")) {
		throw new TypeError("invalid lifecycle preference");
	}
	return Object.freeze(value) as LifecycleClaims;
}

async function frame(claims: LifecycleClaims, body: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
	const fields = [
		claims.audience, claims.action, claims.installation, claims.receiver, String(claims.epoch),
		claims.key_fingerprint, claims.incarnation, claims.predecessor ?? "", String(claims.expiry),
		claims.operation, claims.expected_version === undefined ? "" : String(claims.expected_version), await digest(body),
	].map(value => encoder.encode(value));
	const bytes = new Uint8Array(domain.length + fields.reduce((length, field) => length + 4 + field.length, 0));
	bytes.set(domain);
	const lengths = new DataView(bytes.buffer);
	let offset = domain.length;
	for (const field of fields) {
		lengths.setUint32(offset, field.length);
		offset += 4;
		bytes.set(field, offset);
		offset += field.length;
	}
	return bytes;
}

export async function frameLifecycleProof(body: Uint8Array, audience: string, now: number): Promise<Uint8Array<ArrayBuffer>> {
	const original = new Uint8Array(body);
	return frame(decode(original, audience, now), original);
}

/** A verified signature proves possession only. The caller owns registry and commit checks. */
export async function verifyLifecycleProof(
	body: Uint8Array, signature: Uint8Array, expectedSpki: Uint8Array, audience: string, now: number,
): Promise<LifecycleClaims | null> {
	if (body.length > 2048 || signature.length !== 64 || expectedSpki.length !== 91) return null;
	const original = new Uint8Array(body);
	const proof = new Uint8Array(signature);
	const spki = new Uint8Array(expectedSpki);
	const claims = decode(original, audience, now);
	if (await digest(spki) !== claims.key_fingerprint) return null;
	const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, proof, await frame(claims, original));
	return valid ? claims : null;
}
