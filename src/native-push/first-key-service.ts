import { base64Encode, base64Url } from "../crypto";
import { findInstallTokenByBearer } from "../repositories/installTokens";
import { canonical, need, parseStrictJson, SurfaceError } from "../surface-push/wire";
import {
	firstKeyAudience, firstKeyRegisterBytes, firstKeyStatusBytes,
	type FirstKeyChallenge, type FirstKeyPairBinding, type FirstKeyStatusChallenge,
} from "./first-key-wire";

const prefix = "/v1/push/native/key/";
const routes = ["challenge", "register", "status/challenge", "status"] as const;
const registerBodyLimit = 32_768;
const standardBodyLimit = 16_384;
const appleProofLimit = 16_384;
const originalWindowMs = 120_000;
const statusWindowMs = 15_000;
const currentnessWindowMs = 10_000;
const currentnessHeader = "x-djc-first-key-currentness";
const databaseNowMs = "CAST(unixepoch('subsec') * 1000 AS INTEGER)";
const bindingFields = ["pairing_generation", "pair_binding", "owner_binding", "device_binding", "core_key_thumbprint"] as const;
const challengeFields = ["contract_version", "api_audience", "operation_id", "api_installation_id",
	"install_credential_id", "challenge_id", "challenge_nonce", "expires_at_ms", "expected_key_revision"] as const;
const lookupFields = ["contract_version", "operation_id", "api_installation_id", "transcript_sha256"] as const;
const statusFields = [...lookupFields, "api_audience", "install_credential_id", "pairing_generation",
	"core_key_thumbprint", "expires_at_ms", "status_nonce_id", "status_nonce", "status_nonce_expires_at_ms"] as const;

export function isWidgetFirstKeyRoute(path: string) {
	return routes.some(route => path === prefix + route);
}

type Json = Record<string, unknown>;
type Credential = NonNullable<Awaited<ReturnType<typeof findInstallTokenByBearer>>>;
interface Original extends FirstKeyPairBinding { contract_version: 1; operation_id: string }
interface Currentness extends Original {
	api_audience: typeof firstKeyAudience;
	action: typeof routes[number];
	install_credential_id: string;
	decision_id: string;
	request_sha256: string;
	issued_at_ms: number;
	expires_at_ms: number;
	operation_expires_at_ms: number | null;
}
export type CoreCurrentnessAuthority = (request: Request, decision: Readonly<Currentness>) => Promise<boolean>;
type CheckCurrentness = (original: Original, operationExpiry: number | null, nonceExpiry?: number) => Promise<number>;
interface Retirement extends Original {
	api_audience: typeof firstKeyAudience;
	event_id: string;
	install_credential_id: string;
	request_expires_at_ms: number;
}
interface Lookup { contract_version: 1; operation_id: string; api_installation_id: string; transcript_sha256: string }
interface Saved {
	original_request: string;
	challenge: string;
	expires_at_ms: number;
	key_spki: string | null;
	transcript_sha256: string | null;
	receipt: string | null;
	status_nonce: string | null;
	status_nonce_id: string | null;
	status_expires_at_ms: number | null;
}
interface AppleProof { kind: "attestation"; key_id_b64: string; proof_b64: string }

/** The caller supplies a pairing binding already resolved by trusted Core authority. */
export async function retireWidgetFirstKeyPair(db: D1Database, pairBinding: string): Promise<void> {
	need(hexDigest(pairBinding));
	await db.prepare(`INSERT INTO widget_first_key_retirements (pair_binding) VALUES (?)
		ON CONFLICT(pair_binding) DO NOTHING`).bind(pairBinding).run();
}

/** Trusted composition, never selected by the request. The live implementation must bind
 * this policy ID to the signed app selection and verify App Attest against the saved transcript. */
export interface WidgetFirstKeyPolicy {
	readonly id: string;
	readonly expiresAt: number;
	isCurrent(): boolean;
	isPairCurrent(credentialId: string, original: Readonly<Original>): Promise<boolean>;
	verifyApple(attestation: Uint8Array<ArrayBuffer>, keyId: string, transcript: Uint8Array<ArrayBuffer>,
		expiresAt: number, signal: AbortSignal): Promise<boolean>;
}

function fields(value: unknown, keys: readonly string[]): asserts value is Json {
	need(value !== null && typeof value === "object" && !Array.isArray(value));
	need(Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
}
const select = (value: Json, keys: readonly string[]) => Object.fromEntries(keys.map(key => [key, value[key]]));
const equal = (a: unknown, b: unknown) => canonical(a) === canonical(b);
const id = (value: unknown) => typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const hexDigest = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const nonce = () => base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer);
const digest = async (bytes: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
const hex = (bytes: Uint8Array) => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");

function decode64(value: unknown, size: number, url = false) {
	need(typeof value === "string" && value.length <= Math.ceil(size / 3) * 4 &&
		(url ? /^[A-Za-z0-9_-]+$/ : /^[A-Za-z0-9+/]+={0,2}$/).test(value));
	let raw: string;
	try { raw = atob(url ? value.replaceAll("-", "+").replaceAll("_", "/") : value); }
	catch { throw new SurfaceError(400, "invalid_request"); }
	const bytes = Uint8Array.from(raw, ch => ch.charCodeAt(0));
	need(bytes.length > 0 && bytes.length <= size &&
		(url ? base64Url(bytes.buffer) : base64Encode(bytes)) === value);
	return bytes;
}

export async function readFirstKeyBody(request: Request, limit: number, requireCanonical = false) {
	need(request.headers.get("content-type")?.toLowerCase() === "application/json", "unsupported_media_type", 415);
	need(!request.headers.has("content-encoding"));
	const reader = request.body?.getReader();
	need(reader);
	const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
	let size = 0;
	let text = "";
	try {
		for (;;) {
			const { value, done } = await reader.read();
			if (done) break;
			size += value.byteLength;
			need(size <= limit, "payload_too_large", 413);
			text += decoder.decode(value, { stream: true });
		}
		text += decoder.decode();
		const value = parseStrictJson(text);
		need(!requireCanonical || canonical(value) === text);
		return value;
	} catch (error) {
		await reader.cancel().catch(() => {});
		throw error instanceof SurfaceError ? error : new SurfaceError(400, "invalid_json");
	}
}

async function verifyCore(bytes: Uint8Array<ArrayBuffer>, spki: Uint8Array<ArrayBuffer>, signature: Uint8Array<ArrayBuffer>) {
	need(signature.length === 64);
	let key: CryptoKey;
	try { key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]); }
	catch { throw new SurfaceError(403, "widget_first_key_proof_rejected"); }
	need(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, bytes),
		"widget_first_key_proof_rejected", 403);
}

function json(body: unknown, status = 200) {
	return Response.json(body, { status, headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
}

/** Candidate for a private ingress. Authorization must resolve the exact historical
 * pairing from a separately authenticated Core identity, including after token rotation. */
export function createWidgetFirstKeyRetirementHandler(db: D1Database, origin: string,
	authorize: (request: Request, event: Readonly<Retirement>) => Promise<boolean>) {
	return async (request: Request) => {
		try {
			need(request.method === "POST" && request.url === origin + prefix + "retire",
				"widget_first_key_not_found", 404);
			const input = await readFirstKeyBody(request, 4096, true);
			fields(input, ["contract_version", "api_audience", "event_id", "operation_id", "install_credential_id",
				"request_expires_at_ms", ...bindingFields]);
			need(input.contract_version === 1 && input.api_audience === firstKeyAudience &&
				id(input.operation_id) && input.event_id === input.operation_id && id(input.install_credential_id) &&
				id(input.pairing_generation) && bindingFields.slice(1).every(key => hexDigest(input[key])) &&
				typeof input.request_expires_at_ms === "number" && Number.isSafeInteger(input.request_expires_at_ms) &&
				input.request_expires_at_ms > 0);
			const event = Object.freeze(input as unknown as Retirement);
			need(await authorize(request, event) === true, "widget_first_key_proof_rejected", 403);
			const eventDigest = hex(await digest(Uint8Array.from(new TextEncoder().encode(canonical(event)))));
			need(!request.signal.aborted, "widget_first_key_conflict", 409);
			await retireWidgetFirstKeyPair(db, event.pair_binding);
			return new Response(canonical({
				contract_version: 1, api_audience: firstKeyAudience, event_id: event.event_id,
				pair_binding: event.pair_binding, event_sha256: eventDigest, state: "retired",
			}), { headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" } });
		} catch (error) {
			return error instanceof SurfaceError ? json({ error: error.code }, error.status)
				: json({ error: "widget_first_key_unavailable" }, 503);
		}
	};
}

export function createWidgetFirstKeyHandler(db: D1Database, origin: string, isWorkerCurrent: () => boolean,
	policy?: WidgetFirstKeyPolicy, authorizeCore?: CoreCurrentnessAuthority) {
	const policyId = policy?.id;
	const policyExpiry = policy?.expiresAt;
	const credentialGuard = `EXISTS (SELECT 1 FROM install_tokens WHERE id = ? AND token_hash = ? AND disabled = 0)`;
	const pairGuard = `NOT EXISTS (SELECT 1 FROM widget_first_key_retirements WHERE pair_binding = ?)`;
	const credentialValues = (credential: Credential) => [credential.id, credential.token_hash] as const;
	const activeRow = `credential_id = ? AND operation_id = ? AND policy_id = ? AND retired = 0
		AND expires_at_ms > ? AND ${credentialGuard}
		AND NOT EXISTS (SELECT 1 FROM widget_first_key_retirements
			WHERE pair_binding = widget_first_key.pair_binding)`;
	const activeValues = (credential: Credential, operation: string) =>
		[credential.id, operation, policyId!, Date.now(), ...credentialValues(credential)] as const;
	const unavailable = "widget_first_key_unavailable";
	const conflict = "widget_first_key_conflict";

	const checkWorker = () => {
		need(policy && id(policyId) && Number.isSafeInteger(policyExpiry) &&
			policy.id === policyId && policy.expiresAt === policyExpiry &&
			Date.now() < policyExpiry! && isWorkerCurrent() && policy.isCurrent(), unavailable, 503);
		return policy;
	};
	async function checkPair(credential: Credential, original: Original) {
		need(await checkWorker().isPairCurrent(credential.id, Object.freeze(original)), "widget_first_key_proof_rejected", 403);
		checkWorker();
	}
	const load = (credential: Credential, operation: string) =>
		db.prepare(`SELECT * FROM widget_first_key WHERE ${activeRow}`).bind(...activeValues(credential, operation)).first<Saved>();

	async function issueChallenge(input: unknown, credential: Credential, currentness: CheckCurrentness) {
		fields(input, ["contract_version", "operation_id", ...bindingFields]);
		need(input.contract_version === 1 && id(input.operation_id) && id(input.pairing_generation) &&
			bindingFields.slice(1).every(key => hexDigest(input[key])));
		const original = input as unknown as Original;
		await checkPair(credential, original);
		const decisionExpiry = await currentness(original, null);
		const challenge: FirstKeyChallenge = {
			contract_version: 1, api_audience: firstKeyAudience, operation_id: original.operation_id,
			api_installation_id: crypto.randomUUID(), install_credential_id: credential.id,
			challenge_id: crypto.randomUUID(), challenge_nonce: nonce(),
			expires_at_ms: Math.min(Date.now() + originalWindowMs, policyExpiry!), expected_key_revision: 0,
		};
		await db.prepare(`INSERT INTO widget_first_key
			(credential_id, operation_id, installation_id, policy_id, pair_binding, original_request, challenge, expires_at_ms)
			SELECT ?, ?, ?, ?, ?, ?, ?, ? WHERE ${credentialGuard} AND ${pairGuard} AND ? > ${databaseNowMs}
			ON CONFLICT(credential_id, operation_id) DO NOTHING`)
			.bind(credential.id, original.operation_id, challenge.api_installation_id, policyId!,
				original.pair_binding, canonical(original), canonical(challenge), challenge.expires_at_ms,
				...credentialValues(credential), original.pair_binding, decisionExpiry).run();
		const saved = await load(credential, original.operation_id);
		need(saved && saved.original_request === canonical(original) && !saved.receipt, conflict, 409);
		return JSON.parse(saved.challenge) as FirstKeyChallenge;
	}

	async function register(input: Json, credential: Credential, proof: AppleProof, signal: AbortSignal, currentness: CheckCurrentness) {
		need(id(input.operation_id));
		const saved = await load(credential, input.operation_id as string);
		need(saved && !saved.receipt, conflict, 409);
		const original = JSON.parse(saved.original_request) as Original;
		const challenge = JSON.parse(saved.challenge) as FirstKeyChallenge;
		need(equal(select(input, challengeFields), challenge) &&
			equal(select(input, bindingFields), select(original as unknown as Json, bindingFields)), conflict, 409);
		const bytes = firstKeyRegisterBytes(challenge, original);
		const spki = decode64(input.core_public_key_spki_b64, 160);
		need(hex(await digest(spki)) === original.core_key_thumbprint, "widget_first_key_proof_rejected", 403);
		await verifyCore(bytes, spki, decode64(input.core_signature_b64url, 64, true));
		need(decode64(proof.key_id_b64, 32).length === 32);
		const attestation = decode64(proof.proof_b64, appleProofLimit);
		const hash = await digest(bytes);
		await checkPair(credential, original);
		await currentness(original, challenge.expires_at_ms);
		need(await checkWorker().verifyApple(attestation, proof.key_id_b64, bytes, challenge.expires_at_ms, signal),
			"widget_first_key_proof_rejected", 403);
		await checkPair(credential, original);
		const decisionExpiry = await currentness(original, challenge.expires_at_ms);
		need(!signal.aborted, conflict, 409);
		const receipt = {
			contract_version: 1, operation_id: original.operation_id, api_installation_id: challenge.api_installation_id,
			install_credential_id: credential.id, pairing_generation: original.pairing_generation,
			registry_generation: crypto.randomUUID(), key_revision: 1, core_key_thumbprint: original.core_key_thumbprint,
			transcript_sha256: hex(hash), expires_at_ms: challenge.expires_at_ms, state: "registered",
		};
		const result = await db.prepare(`UPDATE widget_first_key SET key_spki = ?, transcript_sha256 = ?, receipt = ?
			WHERE ${activeRow} AND challenge = ? AND receipt IS NULL AND ? > ${databaseNowMs}
			AND NOT EXISTS (SELECT 1 FROM widget_first_key WHERE pair_binding = ? AND receipt IS NOT NULL)
			RETURNING receipt`).bind(input.core_public_key_spki_b64, receipt.transcript_sha256, canonical(receipt),
			...activeValues(credential, original.operation_id), saved.challenge, decisionExpiry, original.pair_binding).first<{ receipt: string }>();
		need(result, conflict, 409);
		return JSON.parse(result.receipt) as typeof receipt;
	}

	function lookup(input: Json) {
		need(input.contract_version === 1 && id(input.operation_id) && id(input.api_installation_id) && hexDigest(input.transcript_sha256));
		return input as unknown as Lookup;
	}

	async function issueStatus(input: unknown, credential: Credential, currentness: CheckCurrentness): Promise<FirstKeyStatusChallenge> {
		fields(input, lookupFields);
		const query = lookup(input);
		const saved = await load(credential, query.operation_id);
		need(saved?.receipt && saved.transcript_sha256 === query.transcript_sha256, conflict, 409);
		const challenge = JSON.parse(saved.challenge) as FirstKeyChallenge;
		need(challenge.api_installation_id === query.api_installation_id, conflict, 409);
		const original = JSON.parse(saved.original_request) as Original;
		await checkPair(credential, original);
		const decisionExpiry = await currentness(original, saved.expires_at_ms);
		const now = Date.now();
		const newNonce = nonce(), newId = crypto.randomUUID(), expires = Math.min(now + statusWindowMs, saved.expires_at_ms);
		const issued = await db.prepare(`UPDATE widget_first_key SET status_nonce = ?, status_nonce_id = ?, status_expires_at_ms = ?
			WHERE ${activeRow} AND receipt = ? AND (status_nonce_id IS NULL OR status_expires_at_ms <= ?) AND ? > ${databaseNowMs}
			RETURNING status_nonce, status_nonce_id, status_expires_at_ms`)
			.bind(newNonce, newId, expires, ...activeValues(credential, query.operation_id), saved.receipt, now, decisionExpiry).first<Saved>();
		const outstanding = issued ?? await load(credential, query.operation_id);
		need(outstanding?.status_nonce && outstanding.status_nonce_id &&
			outstanding.status_expires_at_ms && outstanding.status_expires_at_ms > Date.now(), conflict, 409);
		return { ...query, api_audience: firstKeyAudience, install_credential_id: credential.id,
			pairing_generation: original.pairing_generation, core_key_thumbprint: original.core_key_thumbprint,
			expires_at_ms: saved.expires_at_ms, status_nonce_id: outstanding.status_nonce_id,
			status_nonce: outstanding.status_nonce, status_nonce_expires_at_ms: outstanding.status_expires_at_ms };
	}

	async function readStatus(input: unknown, credential: Credential, currentness: CheckCurrentness) {
		fields(input, [...statusFields, "core_signature_b64url"]);
		const query = lookup(input);
		const saved = await load(credential, query.operation_id);
		need(saved?.receipt && saved.key_spki && saved.transcript_sha256 === query.transcript_sha256, conflict, 409);
		const original = JSON.parse(saved.original_request) as Original;
		const challenge = JSON.parse(saved.challenge) as FirstKeyChallenge;
		need(challenge.api_installation_id === query.api_installation_id && saved.status_nonce && saved.status_nonce_id &&
			saved.status_expires_at_ms && saved.status_expires_at_ms > Date.now(), conflict, 409);
		const expected: FirstKeyStatusChallenge = { contract_version: 1, operation_id: query.operation_id,
			api_installation_id: query.api_installation_id, transcript_sha256: query.transcript_sha256,
			api_audience: firstKeyAudience, install_credential_id: credential.id,
			pairing_generation: original.pairing_generation, core_key_thumbprint: original.core_key_thumbprint,
			expires_at_ms: saved.expires_at_ms, status_nonce_id: saved.status_nonce_id,
			status_nonce: saved.status_nonce, status_nonce_expires_at_ms: saved.status_expires_at_ms };
		need(equal(select(input, statusFields), expected), conflict, 409);
		await verifyCore(firstKeyStatusBytes(expected), decode64(saved.key_spki, 160), decode64(input.core_signature_b64url, 64, true));
		await checkPair(credential, original);
		const decisionExpiry = await currentness(original, saved.expires_at_ms, saved.status_expires_at_ms);
		const consumed = await db.prepare(`UPDATE widget_first_key
			SET status_nonce = NULL, status_nonce_id = NULL, status_expires_at_ms = NULL
			WHERE ${activeRow} AND receipt = ? AND status_nonce_id = ? AND status_expires_at_ms > ? AND ? > ${databaseNowMs}
			RETURNING receipt`).bind(...activeValues(credential, query.operation_id), saved.receipt,
			saved.status_nonce_id, Date.now(), decisionExpiry).first<{ receipt: string }>();
		need(consumed, conflict, 409);
		return JSON.parse(consumed.receipt);
	}

	return async (request: Request) => {
		try {
			const { pathname } = new URL(request.url);
			need(request.method === "POST" && isWidgetFirstKeyRoute(pathname) && request.url === origin + pathname,
				"widget_first_key_not_found", 404);
			checkWorker();
			const match = /^Bearer (djci_[A-Za-z0-9_-]{1,256})$/.exec(request.headers.get("authorization") ?? "");
			need(match, "install_auth_required", 401);
			const route = pathname.slice(prefix.length) as typeof routes[number];
			const authenticate = async () => {
				checkWorker();
				const credential = await findInstallTokenByBearer(db, match[1]);
				need(credential, "install_auth_required", 401);
				checkWorker();
				return credential;
			};
			const authenticated = route !== "register" ? await authenticate() : undefined;
			const input = await readFirstKeyBody(request, route === "register" ? registerBodyLimit : standardBodyLimit, !!authorizeCore);
			let proof: AppleProof | undefined;
			if (route === "register") {
				fields(input, [...challengeFields, ...bindingFields, "core_public_key_spki_b64", "core_signature_b64url", "apple_proof"]);
				fields(input.apple_proof, ["kind", "key_id_b64", "proof_b64"]);
				need(input.apple_proof.kind !== "assertion", "widget_first_key_proof_rejected", 403);
				need(input.apple_proof.kind === "attestation");
				proof = input.apple_proof as unknown as AppleProof;
			}
			const credential = authenticated ?? await authenticate();
			let checkFresh = () => {};
			let currentness: CheckCurrentness = async () => Number.MAX_SAFE_INTEGER;
			if (authorizeCore) {
				const rejected = "widget_first_key_proof_rejected";
				const header = request.headers.get(currentnessHeader);
				need(header && header.length <= 2048, rejected, 403);
				const decisionInput = parseStrictJson(header);
				fields(decisionInput, ["contract_version", "api_audience", "action", "decision_id", "install_credential_id",
					"operation_id", ...bindingFields, "request_sha256", "issued_at_ms", "expires_at_ms", "operation_expires_at_ms"]);
				need(canonical(decisionInput) === header && decisionInput.api_audience === firstKeyAudience &&
					decisionInput.action === route && id(decisionInput.decision_id) &&
					decisionInput.install_credential_id === credential.id &&
					Number.isSafeInteger(decisionInput.issued_at_ms) && Number.isSafeInteger(decisionInput.expires_at_ms),
					rejected, 403);
				const requestDigest = hex(await digest(Uint8Array.from(new TextEncoder().encode(canonical(input)))));
				need(decisionInput.request_sha256 === requestDigest, rejected, 403);
				const decision = Object.freeze(decisionInput as unknown as Currentness);
				checkFresh = () => {
					const now = Date.now();
					need(!request.signal.aborted && decision.issued_at_ms > 0 &&
						decision.issued_at_ms <= now && now < decision.expires_at_ms &&
						decision.expires_at_ms - decision.issued_at_ms <= currentnessWindowMs, rejected, 403);
				};
				let claimed = false;
				currentness = async (original, operationExpiry, nonceExpiry) => {
					checkFresh();
					need(equal(select(decisionInput, ["contract_version", "operation_id", ...bindingFields]), original) &&
						decision.operation_expires_at_ms === operationExpiry &&
						decision.expires_at_ms <= (operationExpiry ?? Infinity) &&
						decision.expires_at_ms <= (nonceExpiry ?? Infinity), rejected, 403);
					need(await authorizeCore(request, decision) === true, rejected, 403);
					checkFresh();
					checkWorker();
					if (!claimed) {
						await db.prepare(`DELETE FROM widget_first_key_decisions WHERE rowid IN (
							SELECT rowid FROM widget_first_key_decisions WHERE expires_at_ms <= ${databaseNowMs} LIMIT 32)`).run();
						const claim = await db.prepare(`INSERT INTO widget_first_key_decisions (credential_id, decision_id, expires_at_ms)
							SELECT ?, ?, ? WHERE ? > ${databaseNowMs}
							ON CONFLICT(credential_id, decision_id) DO NOTHING RETURNING decision_id`)
							.bind(credential.id, decision.decision_id, decision.expires_at_ms, decision.expires_at_ms).first();
						need(claim, conflict, 409);
						claimed = true;
					}
					checkFresh();
					checkWorker();
					return decision.expires_at_ms;
				};
			}
			let result: unknown;
			if (proof) {
				result = await register(input as Json, credential, proof, request.signal, currentness);
			} else {
				const handlers = { challenge: issueChallenge, "status/challenge": issueStatus, status: readStatus };
				need(route !== "register");
				result = await handlers[route](input, credential, currentness);
			}
			checkFresh();
			checkWorker();
			return json(result);
		} catch (error) {
			return error instanceof SurfaceError ? json({ error: error.code }, error.status) : json({ error: unavailable }, 503);
		}
	};
}
