/** LOCAL QA contract only. Evidence is sensitive and cannot authorize/persist a key by itself. */
export interface SavedEnrollmentState {
  policy:{id:'ios-dev-qualification/1';revision:string;enabled:boolean;expiresAt:number};
  challenge:{id:string;keyId:string;action:'register';createdAt:number;expiresAt:number;clientData:Uint8Array};
}
export interface EnrollmentEvidence {
  scope:'COMPOSED_PRIVATE_EVIDENCE_ONLY_NO_ATOMIC_REGISTRATION'|'SOFTWARE_STUB_COMPOSITION_ONLY_NOT_CRYPTO_OR_ENROLLMENT_PROOF';
  keyId:string;challengeId:string;challengeCreatedAt:number;challengeExpiresAt:number;
  policy:'ios-dev-qualification/1';policyRevision:string;verifiedAt:number;validUntil:number;
  publicPoint:Uint8Array;initialReceipt:Uint8Array;receiptCreatedAt:number;
}
/** Saved-state callback failures reject unchanged for owning-coordinator classification. */
export interface EnrollmentVerifier {
  verify(request:{challengeId:string;keyId:string;attestation:Uint8Array}):Promise<
    {ok:true;evidence:EnrollmentEvidence}|{ok:false;error:'enrollment_rejected'|'attestation_unavailable'}>;
}
export function createEnrollmentEvidenceVerifier(readState:()=>SavedEnrollmentState):EnrollmentVerifier;
/** Dependency injection is restricted to explicit software orchestration fixtures. Never a request parameter. */
export function createSoftwareStubEnrollmentVerifier(readState:()=>SavedEnrollmentState,components:{
  core:(...args:unknown[])=>Promise<unknown>;cms:(...args:unknown[])=>Promise<unknown>;
  status:{check:(...args:unknown[])=>Promise<unknown>};
}):EnrollmentVerifier;
