import { base64Url } from "../../src/crypto";
import { findInstallTokenByBearer } from "../../src/repositories/installTokens";
import { bytes } from "../../src/surface-push/issuer-wire";
import { canonical, need } from "../../src/surface-push/wire";

export const schema = [
	"CREATE TABLE trial_retired_pair (pair TEXT PRIMARY KEY)",
	`CREATE TABLE trial_widget_challenge (
		id TEXT PRIMARY KEY, nonce TEXT NOT NULL, token_id TEXT NOT NULL, token_hash TEXT NOT NULL,
		installation TEXT NOT NULL, pair TEXT NOT NULL, device TEXT NOT NULL, app_key TEXT NOT NULL, target TEXT NOT NULL,
		expires INTEGER NOT NULL, state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked'))
	)`,
];

interface Scope {
	installation: string;
	pair: string;
	device: string;
	appKey: string;
	target: string;
}

interface Challenge extends Scope {
	credentialId: string;
	id: string;
	nonce: string;
	expires: number;
}

interface Saved extends Omit<Challenge, "appKey" | "credentialId"> {
	app_key: string;
	token_id: string;
	token_hash: string;
	state: string;
}

interface CapturedPair {
	readonly scope: Readonly<Scope>;
	isCurrent(): Promise<boolean>;
}

interface TrialPorts {
	db: D1Database;
	now(): number;
	capturePair(scope: Readonly<Scope>): Promise<CapturedPair | null>;
	verifyHostProof(input: Uint8Array, proof: Uint8Array, pair: Readonly<CapturedPair>): Promise<boolean>;
}

export function widgetStatement(action: "opt_in" | "opt_out", challenge: Challenge) {
	return new TextEncoder().encode(canonical([
		"djc-native-widget-trial/1", "ha-dev-widget", action, challenge.id, challenge.nonce,
		challenge.installation, challenge.credentialId, challenge.pair, challenge.device, challenge.appKey, challenge.target, challenge.expires,
	]));
}

const sameScope = (first: Scope, second: Scope) =>
	first.installation === second.installation && first.pair === second.pair && first.device === second.device &&
	first.appKey === second.appKey && first.target === second.target;

/** Unmounted wire trial. The real Core capture and native verifier are ports. */
export function createWidgetWireTrial({ db, now, capturePair, verifyHostProof }: TrialPorts) {
	const liveCredential = `EXISTS (SELECT 1 FROM install_tokens
		WHERE id = ? AND token_hash = ? AND disabled = 0)`;
	const currentPair = `NOT EXISTS (SELECT 1 FROM trial_retired_pair WHERE pair = ?)`;
	const selectedWidget = "pair = ? AND device = ? AND target = ?";
	const denied = "widget_trial_denied";
	const challengeRow = (id: string) =>
		db.prepare("SELECT * FROM trial_widget_challenge WHERE id = ?").bind(id).first<Saved>();
	const readCredential = async (bearer: string) => {
		need(/^djci_[A-Za-z0-9_-]+$/.test(bearer), denied, 401);
		const credential = await findInstallTokenByBearer(db, bearer);
		need(credential, denied, 401);
		return credential;
	};

	const checkPair = async (scope: Scope) => {
		const pairing = await capturePair(scope);
		need(pairing && sameScope(pairing.scope, scope) && await pairing.isCurrent(), denied, 403);
		return pairing;
	};

	async function verify(action: "opt_in" | "opt_out", bearer: string, proposed: Challenge, proof: string) {
		const challenge = Object.freeze({ ...proposed });
		const credential = await readCredential(bearer);
		const saved = await challengeRow(challenge.id);
		need(saved && saved.token_id === credential.id && challenge.credentialId === credential.id &&
			saved.token_hash === credential.token_hash &&
			saved.nonce === challenge.nonce && saved.expires === challenge.expires &&
			sameScope({ ...saved, appKey: saved.app_key }, challenge), denied, 403);
		const pairing = await checkPair(challenge);
		need(await verifyHostProof(widgetStatement(action, challenge), bytes(proof, 64), pairing), denied, 403);
		need(await pairing.isCurrent(), denied, 403);
		return { challenge, credential };
	}

	return {
		async challenge(bearer: string, requested: Scope) {
			const scope = Object.freeze({ ...requested });
			const credential = await readCredential(bearer);
			need(credential.ha_install_id === scope.installation, denied, 403);
			await checkPair(scope);
			const result = {
				...scope, credentialId: credential.id, id: crypto.randomUUID(), nonce: base64Url(crypto.getRandomValues(new Uint8Array(32)).buffer),
				expires: now() + 60_000,
			};
			const write = await db.prepare(`INSERT INTO trial_widget_challenge
				SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending' WHERE ${liveCredential} AND ${currentPair}`).bind(
				result.id, result.nonce, credential.id, credential.token_hash,
				result.installation, result.pair, result.device, result.appKey, result.target, result.expires,
				credential.id, credential.token_hash, result.pair,
			).run();
			need(write.meta.changes === 1, denied, 403);
			return result;
		},
		async optIn(bearer: string, challenge: Challenge, proof: string) {
			const verified = await verify("opt_in", bearer, challenge, proof);
			const original = verified.challenge;
			const write = await db.prepare(`UPDATE trial_widget_challenge SET state = 'active'
				WHERE id = ? AND state = 'pending' AND expires > ?
				AND ${liveCredential} AND ${currentPair}
				AND NOT EXISTS (SELECT 1 FROM trial_widget_challenge WHERE ${selectedWidget} AND state = 'active')`).bind(
				original.id, now(), verified.credential.id, verified.credential.token_hash, original.pair,
				original.pair, original.device, original.target,
			).run();
			need(write.meta.changes === 1, denied, 409);
			return { registrationId: original.id, state: "active" };
		},
		async optOut(bearer: string, challenge: Challenge, proof: string) {
			const verified = await verify("opt_out", bearer, challenge, proof);
			const original = verified.challenge;
			const { id, token_hash: hash } = verified.credential;
			const [, write] = await db.batch([
				db.prepare(`UPDATE trial_widget_challenge SET state = 'revoked'
					WHERE ${selectedWidget} AND state = 'pending' AND ${liveCredential}
					AND EXISTS (SELECT 1 FROM trial_widget_challenge WHERE id = ? AND state = 'active')`)
					.bind(original.pair, original.device, original.target, id, hash, original.id),
				db.prepare(`UPDATE trial_widget_challenge SET state = 'revoked'
					WHERE id = ? AND state = 'active' AND ${liveCredential}`).bind(original.id, id, hash),
			]);
			need(write.meta.changes === 1, denied, 409);
			return { registrationId: verified.challenge.id, state: "revoked" };
		},
		async unlink(original: CapturedPair) {
			need(await original.isCurrent(), denied, 403);
			const pair = original.scope.pair;
			await db.batch([
				db.prepare("INSERT OR IGNORE INTO trial_retired_pair VALUES (?)").bind(pair),
				db.prepare("UPDATE trial_widget_challenge SET state = 'revoked' WHERE pair = ?").bind(pair),
			]);
		},
	};
}
