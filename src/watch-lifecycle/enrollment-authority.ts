import type { EnrollmentChallenge, EnrollmentIntent } from "./enrollment";

type Grant = Readonly<EnrollmentIntent>;

function binding(grant: Grant): string {
	return JSON.stringify([grant.audience, grant.installation, grant.operator_binding, grant.restore_fence,
		grant.key_fingerprint, grant.expected_epoch, grant.expiry]);
}

/** Private actor state. Only an independently authenticated operator may authorize or revoke. */
export class WatchEnrollmentAuthority {
	constructor(private readonly storage: DurableObjectStorage, private readonly installation: string) {
		storage.sql.exec(`CREATE TABLE IF NOT EXISTS watch_enrollment_authority (
			operator_binding TEXT PRIMARY KEY, binding TEXT NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
		)`);
	}

	async authorize(grant: Grant): Promise<boolean> {
		if (grant.installation !== this.installation || !/^[a-f0-9]{64}$/.test(grant.operator_binding)) return false;
		const inserted = this.storage.sql.exec(`INSERT OR IGNORE INTO watch_enrollment_authority
			(operator_binding,binding) VALUES (?,?) RETURNING operator_binding`,
			grant.operator_binding, binding(grant)).toArray().length === 1;
		if (inserted) await this.storage.sync();
		return inserted;
	}

	async revoke(operatorBinding: string): Promise<boolean> {
		const found = this.storage.sql.exec(`UPDATE watch_enrollment_authority SET revoked=1
			WHERE operator_binding=? RETURNING operator_binding`, operatorBinding).toArray().length === 1;
		if (found) await this.storage.sync();
		return found;
	}

	isAdmitted(grant: Grant): boolean {
		return grant.installation === this.installation && this.storage.sql.exec(`SELECT 1 FROM watch_enrollment_authority
			WHERE operator_binding=? AND binding=? AND revoked=0`,
			grant.operator_binding, binding(grant)).toArray().length === 1;
	}

	assertCurrent(value: Grant | Readonly<EnrollmentChallenge>): void {
		const grant = "challenge_id" in value
			? { ...value, expected_epoch: value.predecessor_epoch ?? 0, expiry: value.expires_at }
			: value;
		if (!this.isAdmitted(grant)) throw new Error("watch_enrollment_authority_unavailable");
	}
}
