/** Erased interface for the real Apple kernel. Crypto output is not enrollment
 * authority: only native-attestation.ts owns its opaque receipt and SQL commit. */
export class NativeAppleProofRejected extends Error {}
export class NativeReceiptStatusUnavailable extends Error {}
export interface NativeAppleEvidencePolicy {
 readonly profile:string;
 readonly app_identifier:string;
 readonly app_attest_environment:string;
 readonly bundle_version:string;
 readonly launch_validation_category_b64:string;
}
export interface NativeAppleEvidenceWindow {
 readonly signal:AbortSignal;
 check():number;
 run<T>(work:()=>Promise<T>,stage?:AbortSignal):Promise<T>;
}
export interface NativeAppleEvidence {
 readonly scope:'APPLE_ATTESTATION_AND_RECEIPT_CRYPTO_STATUS_ONLY_NO_ENROLLMENT';
 readonly public_key_spki_b64:string;
 readonly receipt:Uint8Array;
 readonly receiptCreated:number;
 readonly expires:number;
 readonly attestationPathScope:'APPLE_APPATTEST_PROTOCOL_PATH_VALIDITY_ONLY_NO_REVOCATION_ASSERTION';
 readonly receiptScope:'APPLE_RECEIPT_SIGNATURE_PATH_FIELDS_AND_FRESH_SIGNED_COMMON_STATUS_ONLY_NO_ENROLLMENT';
 readonly statusCheckedAt:number;
 readonly statusExpiresAt:number;
}
/** Runtime validates the supplied saved-policy fields and exact Apple evidence.
 * Malformed proof returns null; unavailable status and unexpected crypto reject.
 * No native SDK call, synthetic result port or automatic enrollment is exposed. */
export function verifyAppleAttestationEvidence(encoded:Uint8Array,clientData:Uint8Array,keyId:string,policy:Readonly<NativeAppleEvidencePolicy>,window:NativeAppleEvidenceWindow,fetcher:typeof fetch):Promise<Readonly<NativeAppleEvidence>|null>;
