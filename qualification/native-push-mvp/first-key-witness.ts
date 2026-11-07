// Proposed closed WidgetKit HA-dev wire. These functions encode public test vectors.
const audience = "djc-native-push-ha-dev/1";
const noncePattern = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const identifierPattern = /^[A-Za-z0-9_-]{1,128}$/;
const digestPattern = /^[0-9a-f]{64}$/;

export interface FirstKeyChallenge {
	contract_version: 1;
	api_audience: typeof audience;
	operation_id: string;
	api_installation_id: string;
	install_credential_id: string;
	challenge_id: string;
	challenge_nonce: string;
	expires_at_ms: number;
	expected_key_revision: 0;
}

export interface FirstKeyPairBinding {
	pairing_generation: string;
	pair_binding: string;
	owner_binding: string;
	device_binding: string;
	core_key_thumbprint: string;
}

export function firstKeyRegisterBytes(challenge: FirstKeyChallenge, binding: FirstKeyPairBinding): Uint8Array<ArrayBuffer> {
	const ids = [challenge.operation_id, challenge.api_installation_id, challenge.install_credential_id,
		challenge.challenge_id, binding.pairing_generation];
	const digests = [binding.pair_binding, binding.owner_binding, binding.device_binding, binding.core_key_thumbprint];
	if (challenge.contract_version !== 1 || challenge.api_audience !== audience || challenge.expected_key_revision !== 0 ||
		!ids.every(id => typeof id === "string" && identifierPattern.test(id)) ||
		!digests.every(hash => typeof hash === "string" && digestPattern.test(hash)) ||
		typeof challenge.challenge_nonce !== "string" || !noncePattern.test(challenge.challenge_nonce) ||
		!Number.isSafeInteger(challenge.expires_at_ms) || challenge.expires_at_ms <= 0) {
		throw new TypeError("invalid first key witness");
	}
	return new TextEncoder().encode(JSON.stringify([
		"djc-native-pair-witness/1", audience, "POST", "/v1/push/native/key/register", "widget-first-key",
		challenge.operation_id, challenge.api_installation_id, challenge.install_credential_id,
		challenge.challenge_id, challenge.challenge_nonce, challenge.expires_at_ms, challenge.expected_key_revision,
		binding.pairing_generation, binding.pair_binding, binding.owner_binding, binding.device_binding, binding.core_key_thumbprint,
	]));
}
