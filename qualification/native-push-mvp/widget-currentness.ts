// Proposed HA-dev WidgetKit contract; unmounted. Core signs these exact bytes.
export const widgetIssueRoute = "/v1/push/native/enrollment/issue";

export interface WidgetCurrentness {
	operationId: string;
	nonce: string;
	deadlineMs: number;
	apiInstallationId: string;
	installCredentialId: string;
	coreKeyThumbprint: string;
	keyRevision: number;
	pairingGeneration: string;
	pairBinding: string;
	ownerBinding: string;
	deviceBinding: string;
	consentGeneration: string;
	targetDigest: string;
	purposeKeyThumbprint: string;
	registrationId: string;
	requestDigest: string;
}

export function widgetCurrentnessBytes(s: Readonly<WidgetCurrentness>): Uint8Array<ArrayBuffer> {
	const ids = [s.operationId, s.apiInstallationId, s.installCredentialId, s.pairingGeneration,
		s.consentGeneration, s.registrationId];
	const digests = [s.coreKeyThumbprint, s.pairBinding, s.ownerBinding, s.deviceBinding,
		s.targetDigest, s.purposeKeyThumbprint, s.requestDigest];
	if (!ids.every(id => typeof id === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(id)) ||
		!digests.every(hash => typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash)) ||
		typeof s.nonce !== "string" || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(s.nonce) ||
		!Number.isSafeInteger(s.deadlineMs) || s.deadlineMs <= 0 ||
		!Number.isSafeInteger(s.keyRevision) || s.keyRevision <= 0) throw new TypeError("invalid widget confirmation");
	return new TextEncoder().encode(JSON.stringify([
		"djc-native-widget-currentness/1", "djc-native-push-ha-dev/1", "POST", widgetIssueRoute, "opt_in",
		s.operationId, s.nonce, s.deadlineMs, s.apiInstallationId, s.installCredentialId,
		s.coreKeyThumbprint, s.keyRevision, s.pairingGeneration, s.pairBinding, s.ownerBinding, s.deviceBinding,
		"widget", "widget", s.consentGeneration, s.targetDigest, s.purposeKeyThumbprint, s.registrationId, s.requestDigest,
	]));
}
