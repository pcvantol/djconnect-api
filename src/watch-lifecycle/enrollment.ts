interface EnrollmentChallenge {
	challenge_id: string;
	audience: string;
	installation: string;
	operator_binding: string;
	restore_fence: string;
	nonce_hash: string;
	key_fingerprint: string;
	public_spki_hex: string;
	epoch: number;
	predecessor_epoch: number | null;
	expires_at: number;
}

interface EnrollmentAuthority {
	/** Owning composition verifies actual operator and independent restore admission. Throws on denial. */
	assertCurrent(challenge: Readonly<EnrollmentChallenge>): void;
}

export interface IssuerReceipt {
	installation: string;
	epoch: number;
	key_fingerprint: string;
	scope: "watch-lifecycle";
}

const encoder = new TextEncoder();

async function hash(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
		byte => byte.toString(16).padStart(2, "0")).join("");
}

function frame(challenge: Readonly<EnrollmentChallenge>, nonce: string): Uint8Array<ArrayBuffer> {
	const domain = encoder.encode("DJC-WATCH-ENROLLMENT-V1\0");
	const fields = [challenge.audience, challenge.installation, challenge.key_fingerprint,
		"watch-lifecycle", String(challenge.predecessor_epoch ?? 0), String(challenge.epoch),
		nonce, String(challenge.expires_at)].map(field => encoder.encode(field));
	const bytes = new Uint8Array(domain.length + fields.reduce((size, field) => size + 4 + field.length, 0));
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

/** Closed qualification primitive. No authority implementation, challenge issuer or HTTP route. */
export async function redeemWatchEnrollment(
	db: D1Database, challengeId: string, nonce: string, signature: Uint8Array, authority: EnrollmentAuthority,
): Promise<IssuerReceipt | null> {
	if (!/^[A-Za-z0-9._~-]{1,160}$/.test(challengeId)
		|| !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(nonce) || signature.length !== 64) return null;
	const { assertCurrent } = authority;
	const proof = new Uint8Array(signature);
	const selected = await db.prepare(`SELECT challenge_id,audience,installation,operator_binding,restore_fence,nonce_hash,
		key_fingerprint,public_spki_hex,epoch,predecessor_epoch,expires_at
		FROM watch_lifecycle_enrollment WHERE challenge_id=? AND consumed=0 AND expires_at-unixepoch() BETWEEN 1 AND 30`)
		.bind(challengeId).first<EnrollmentChallenge>();
	if (!selected) return null;
	const challenge = Object.freeze(selected);
	const check = () => {
		const result: unknown = assertCurrent(challenge);
		if (result !== undefined) {
			void Promise.resolve(result).catch(() => undefined);
			throw new TypeError("enrollment authority must be synchronous");
		}
	};
	check();
	if (!/^[\x21-\x7e]{1,160}$/.test(challenge.audience) || !/^[A-Za-z0-9._~-]{1,160}$/.test(challenge.installation)
		|| !/^[a-f0-9]{182}$/.test(challenge.public_spki_hex)
		|| await hash(new Uint8Array(encoder.encode(nonce))) !== challenge.nonce_hash) return null;
	const spki = new Uint8Array(challenge.public_spki_hex.match(/../g)!.map(pair => parseInt(pair, 16)));
	if (await hash(spki) !== challenge.key_fingerprint) return null;
	const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
	if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, proof, frame(challenge, nonce))) return null;
	const commit = db.prepare(`UPDATE watch_lifecycle_enrollment SET consumed=1
		WHERE challenge_id=?1 AND installation=?2 AND operator_binding=?3 AND restore_fence=?4 AND nonce_hash=?5
			AND key_fingerprint=?6 AND public_spki_hex=?7 AND epoch=?8 AND predecessor_epoch IS ?9 AND expires_at=?10
			AND audience=?11 AND consumed=0 AND expires_at-unixepoch() BETWEEN 1 AND 30
			AND ((predecessor_epoch IS NULL AND epoch=1 AND NOT EXISTS (
				SELECT 1 FROM watch_lifecycle_issuer WHERE installation=?2))
				OR (epoch=predecessor_epoch+1 AND EXISTS (
				SELECT 1 FROM watch_lifecycle_issuer WHERE installation=?2 AND epoch=?9 AND active=0)))
		RETURNING installation,epoch,key_fingerprint,'watch-lifecycle' AS scope`)
		.bind(challenge.challenge_id, challenge.installation, challenge.operator_binding, challenge.restore_fence,
			challenge.nonce_hash, challenge.key_fingerprint, challenge.public_spki_hex, challenge.epoch,
			challenge.predecessor_epoch, challenge.expires_at, challenge.audience);
	check();
	return commit.first<IssuerReceipt>();
}
