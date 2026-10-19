// TEMPORARY LOCAL TEST EXPORTS ONLY. This software class is never a product/default binding.
import {EnrollmentCoordinator,EnrollmentKeyState,type EnrollmentEnv,type RegisterInput} from './enrollment-key-state';
import {createSoftwareStubEnrollmentVerifier,type EnrollmentEvidence} from './enrollment-evidence-candidate.mjs';
import {receiptRoot} from 'djc-enrollment-trust';
import {base64Url,base64Decode} from 'djc-existing-crypto';
export {ReceiptKeyStore} from './receipt-key-store';
export {AssertionKeyState} from './assertion-key-state';
export {EnrollmentCoordinator};
class SoftwareEnrollmentKeyState extends EnrollmentKeyState {
  protected override allowedEvidenceScope():EnrollmentEvidence['scope']{return 'SOFTWARE_STUB_COMPOSITION_ONLY_NOT_CRYPTO_OR_ENROLLMENT_PROOF';}
  protected override verifyEnrollment(request:RegisterInput){
    const data=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(request.attestation)) as {point:string;nonce:string;receipt:string;created:number;deadline:number};
    const read=()=>this.enrollmentSnapshot();
    const components={
      core:async()=>{if(data.nonce!==base64Url(read().challenge.clientData.buffer as ArrayBuffer))return null;return {scope:'ATTESTATION_CORE_ONLY_RECEIPT_UNVERIFIED_NO_ENROLLMENT',point:base64Decode(data.point),receipt:base64Decode(data.receipt),attestedLeaf:new Uint8Array([1]),certificateExpiresAt:data.deadline};},
      cms:async()=>({scope:'CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT',fresh:true,created:data.created,expires:data.deadline,certificateExpiresAt:data.deadline,signer:new Uint8Array([2]),issuer:new Uint8Array([3]),root:receiptRoot}),
      status:{check:async(...args:unknown[])=>{const checkedAt=Date.now();return {ok:true,scope:args[0]==='crl'?'COMMON_RECEIPT_ISSUER_CRL_NOT_LISTED_ONLY_NO_ENROLLMENT':'COMMON_RECEIPT_OCSP_GOOD_ONLY_NO_ENROLLMENT',checkedAt,cacheUntil:data.deadline,thisUpdate:checkedAt,nextUpdate:data.deadline};}},
    };
    return createSoftwareStubEnrollmentVerifier(read,components).verify(request);
  }
}
export class SoftwareEnrollmentCoordinator extends EnrollmentCoordinator {
  constructor(ctx:DurableObjectState,env:EnrollmentEnv){super(ctx,env,SoftwareEnrollmentKeyState);}
}
export default {fetch(){return new Response('qualification only',{status:503,headers:{'cache-control':'no-store'}});}};
