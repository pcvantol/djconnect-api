import {
	verifyAppleAttestationEvidence, type NativeAppleEvidencePolicy,
} from "../../coordinator/host-app-wake-receiving/native-apple-evidence.mjs";
import { RequestWindow } from "../../coordinator/host-app-wake-receiving/request-window";
import type { WidgetFirstKeyPolicy } from "./first-key-service";

/** The policy is supplied by the trusted server composition for one signed app. */
export function createWidgetFirstKeyAppleVerifier(
	policy: Readonly<NativeAppleEvidencePolicy>,
): WidgetFirstKeyPolicy["verifyApple"] {
	const selected = Object.freeze({
		...policy,
		allowed_launch_validation_categories_b64: policy.allowed_launch_validation_categories_b64 &&
			Object.freeze([...policy.allowed_launch_validation_categories_b64]),
	});
	return async (attestation, keyId, transcript, expiresAt, signal) => {
		const remaining = expiresAt - Date.now();
		if (remaining <= 0 || signal.aborted) return false;
		const deadline = AbortSignal.any([signal, AbortSignal.timeout(remaining)]);
		const window = new RequestWindow(Date.now, deadline);
		try {
			// The existing verifier hashes the raw transcript for App Attest.
			const evidence = await verifyAppleAttestationEvidence(attestation, transcript, keyId, selected, window, fetch);
			return evidence !== null && Date.now() < expiresAt;
		} finally {
			window.close();
		}
	};
}
