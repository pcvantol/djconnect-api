import { timingSafeEqualString } from "../crypto";
import { HttpError } from "../http";
import { SurfaceError } from "../surface-push/wire";
import { findInstallTokenByBearer } from "../repositories/installTokens";

export type NativePushChannel = "widget" | "live_activity" | "moment_app" | "watch_smart_stack";

/** Internal coordinates. Core's signed consent wire is a separate boundary. */
export interface NativePushScope {
	installation: string;
	owner: string;
	device: string;
	pairingGeneration: string;
	channel: NativePushChannel;
	consentGeneration: string;
	targetDigest: string;
	purposeKeyThumbprint: string;
}

interface VerifiedPushConsent {
	readonly scope: Readonly<NativePushScope>;
	readonly choice: "opt_in" | "opt_out";
	readonly expiresAt: number;
}

/** A trusted composition port, never a caller-supplied authority or receipt. */
export interface OriginalPushConsentAuthority {
	verifyOriginal(scope: Readonly<NativePushScope>): Promise<VerifiedPushConsent | null>;
	isCurrent(consent: Readonly<VerifiedPushConsent>): Promise<boolean>;
}

const fields = [
	"installation", "owner", "device", "pairingGeneration", "channel",
	"consentGeneration", "targetDigest", "purposeKeyThumbprint",
] as const;

function consentRequired(): never {
	throw new SurfaceError(403, "native_push_consent_required");
}

/** Preflight for issuance and re-enrollment. The owning write must also fence
 * the installation token and consent generation in its commit authority. */
export async function admitNativePushEnrollment(
	request: Request, db: D1Database, input: NativePushScope,
	authority: OriginalPushConsentAuthority, now = Date.now,
) {
	const scope = Object.freeze({ ...input });
	if (!fields.every(field => typeof scope[field] === "string" && scope[field].length > 0) ||
		!["widget", "live_activity", "moment_app", "watch_smart_stack"].includes(scope.channel) ||
		!(/^[a-f0-9]{64}$/.test(scope.targetDigest) && /^[a-f0-9]{64}$/.test(scope.purposeKeyThumbprint))) consentRequired();
	const header = request.headers.get("authorization");
	const match = header?.match(/^Bearer (djci_[A-Za-z0-9_-]+)$/);
	if (!match) throw new HttpError(401, "install_auth_required");
	const bearer = match[1];
	const original = await findInstallTokenByBearer(db, bearer);
	if (!original) throw new HttpError(401, "install_auth_required");
	if (!(await timingSafeEqualString(original.ha_install_id, scope.installation))) throw new HttpError(403, "install_token_scope_mismatch");

	const verified = await authority.verifyOriginal(scope);
	if (!verified || verified.choice !== "opt_in" ||
		!fields.every(field => verified.scope[field] === scope[field])) consentRequired();
	const consent = Object.freeze({ scope, choice: verified.choice, expiresAt: verified.expiresAt });
	const current = () => {
		const clock = now();
		if (request.signal.aborted || !Number.isSafeInteger(clock) || !Number.isSafeInteger(consent.expiresAt) ||
			clock >= consent.expiresAt) consentRequired();
	};
	current();
	if (await authority.isCurrent(consent) !== true) consentRequired();

	const active = await findInstallTokenByBearer(db, bearer);
	if (!active || active.id !== original.id || active.ha_install_id !== original.ha_install_id ||
		active.token_hash !== original.token_hash) throw new HttpError(401, "install_auth_required");
	current();

	return Object.freeze({
		consent,
		installation: Object.freeze({ id: original.id, ha_install_id: original.ha_install_id, token_hash: original.token_hash }),
	});
}
