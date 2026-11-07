import { base64Url, sha256Hex } from "../crypto";
import { parseStrictJson } from "../surface-push/wire";

const VERSION = "djc-watch-ha-dev-core-pairing/1";
const AUDIENCE = "djconnect-watch-ha-dev:core-pairing:v1";
const DOMAIN = "DJC-WATCH-HA-DEV-CORE-PAIRING-V1\0";
const fields = [
	"version", "audience", "registry_id", "declaration_id", "ha_install_id", "device_id",
	"binding_generation", "key_fingerprint", "issued_at", "expires_at",
] as const;
const id = /^[A-Za-z0-9_-]{1,160}$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const encoder = new TextEncoder();

interface CorePairingDeclaration {
	version: typeof VERSION;
	audience: typeof AUDIENCE;
	registry_id: string;
	declaration_id: string;
	ha_install_id: string;
	device_id: string;
	binding_generation: string;
	key_fingerprint: string;
	issued_at: number;
	expires_at: number;
}

interface PendingCorePairing {
	registryId: string;
	declarationId: string;
	installation: string;
	deviceId: string;
	expiresAt: number;
	coreSpki: Uint8Array;
}

function current(declaration: CorePairingDeclaration, now: number): boolean {
	return Number.isSafeInteger(now) && now >= declaration.issued_at && now < declaration.expires_at;
}

/** Verify against the owner-issued request and pinned Core signer. The owner still consumes the request and checks currentness. */
export async function verifyCorePairingDeclaration(
	body: Uint8Array, signature: string, pending: Readonly<PendingCorePairing>,
	now = () => Math.floor(Date.now() / 1000),
): Promise<Readonly<{ declaration: Readonly<CorePairingDeclaration>; declarationHash: string }> | null> {
	if (body.length === 0 || body.length > 2048 || pending.coreSpki.length !== 91 ||
		!/^[A-Za-z0-9_-]{86}$/.test(signature)) return null;
	try {
		const value = parseStrictJson(decoder.decode(body));
		if (typeof value !== "object" || value === null || Array.isArray(value) ||
			Object.keys(value).length !== fields.length || !fields.every(field => Object.hasOwn(value, field))) return null;
		const declaration = Object.freeze(value) as Readonly<CorePairingDeclaration>;
		const { registry_id, declaration_id, ha_install_id, device_id, binding_generation,
			key_fingerprint, issued_at, expires_at } = declaration;
		const startedAt = now();
		if (declaration.version !== VERSION || declaration.audience !== AUDIENCE ||
			typeof registry_id !== "string" || !uuid.test(registry_id) || registry_id !== pending.registryId ||
			typeof declaration_id !== "string" || !id.test(declaration_id) || declaration_id !== pending.declarationId ||
			typeof ha_install_id !== "string" || !id.test(ha_install_id) || ha_install_id !== pending.installation ||
			typeof device_id !== "string" || !id.test(device_id) || device_id !== pending.deviceId ||
			typeof binding_generation !== "string" || !/^[a-f0-9]{32}$/.test(binding_generation) ||
			typeof key_fingerprint !== "string" || !/^[a-f0-9]{64}$/.test(key_fingerprint) ||
			!Number.isSafeInteger(issued_at) || issued_at < 1 || !Number.isSafeInteger(expires_at) ||
			!Number.isSafeInteger(pending.expiresAt) || expires_at > pending.expiresAt ||
			expires_at - issued_at > 30 || !current(declaration, startedAt)) return null;

		const raw = atob(signature.replaceAll("-", "+").replaceAll("_", "/"));
		const proof = Uint8Array.from(raw, character => character.charCodeAt(0));
		if (proof.length !== 64 || base64Url(proof.buffer) !== signature) return null;
		const spki = new Uint8Array(pending.coreSpki);
		const digest = await crypto.subtle.digest("SHA-256", spki);
		const fingerprint = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
		if (fingerprint !== key_fingerprint) return null;

		const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
		const frame = DOMAIN + JSON.stringify(fields.map(field => declaration[field]));
		if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, proof, encoder.encode(frame))) return null;
		const declarationHash = await sha256Hex(frame);
		const checkedAt = now();
		return checkedAt >= startedAt && current(declaration, checkedAt)
			? Object.freeze({ declaration, declarationHash })
			: null;
	} catch {
		return null;
	}
}
