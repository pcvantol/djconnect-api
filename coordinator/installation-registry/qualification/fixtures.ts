import original from '../../installation-principal/qualification/expired-synthetic-records.json';
import {canonical} from '../../../src/surface-push/wire';
import {decodeRecord} from '../../installation-principal/codec-data';
export const U=(n:number)=>`00000000-0000-4000-8000-${n.toString(16).padStart(12,'0')}`;
export const H=(n:number)=>n.toString(16).padStart(64,'0');
const bytes=(text:string)=>Uint8Array.from(new TextEncoder().encode(text));
export async function digest(text:string){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes(text))),v=>v.toString(16).padStart(2,'0')).join('');}
const record=(k:keyof typeof original.records)=>JSON.parse(original.records[k].canonical);
/** Expired synthetic DATA only. Original independent fixture is never edited.
 * Fixed PUBLIC insecure scalar/nonce=1 arithmetic, as existing source168 vectors.
 * No private CryptoKey, randomness, generateKey or sign API is used. */
export async function fixture(id=1, state:{principalID?:string;principalEpoch?:number;revision?:number}={}){
 const generation=original.records.custody_generation_preparation.canonical;
 const receipt=original.records.custody_public_receipt.canonical;
 const subjectValue={...record('installation_principal_subject'),principal_id:state.principalID??`fixture-principal-${id}`,principal_epoch:state.principalEpoch??1};
 const subject=canonical(subjectValue),subjectHash=(await decodeRecord(subject,'installation_principal_subject')).digest;
 const contextValue={...record('bootstrap_admission_context'),subject_sha256:subjectHash,expected_registry_revision:state.revision??0,
  registration_operation_id:U(id*100+2),challenge_id:U(id*100+3),challenge_nonce_sha256:H(id*100+4)};
 const context=canonical(contextValue),contextHash=(await decodeRecord(context,'bootstrap_admission_context')).digest;
 const bodyValue={...JSON.parse(original.R1.canonical),principal_id:subjectValue.principal_id,principal_epoch:subjectValue.principal_epoch,expected_registry_revision:contextValue.expected_registry_revision,
  registration_operation_id:contextValue.registration_operation_id,challenge_id:contextValue.challenge_id,challenge_nonce_sha256:contextValue.challenge_nonce_sha256,
  operator_admission_binding_sha256:contextHash};
 const body=canonical(bodyValue);
 const proof=canonical({...record('bootstrap_proof_preparation'),subject_sha256:subjectHash,admission_context_sha256:contextHash,
  registration_operation_id:contextValue.registration_operation_id,expected_transcript:body});
 const proofHash=(await decodeRecord(proof,'bootstrap_proof_preparation')).digest;
 const intent=canonical({...record('original_admission_intent'),subject_sha256:subjectHash,admission_context_sha256:contextHash,
  registration_operation_id:contextValue.registration_operation_id,challenge_id:contextValue.challenge_id,challenge_nonce_sha256:contextValue.challenge_nonce_sha256,
  expected_registry_revision:contextValue.expected_registry_revision,bootstrap_preparation_sha256:proofHash});
 const intentHash=(await decodeRecord(intent,'original_admission_intent')).digest;
 const withdrawal=canonical({...record('original_operation_withdrawal_preparation'),subject_sha256:subjectHash,
  registration_operation_id:contextValue.registration_operation_id,registration_challenge_id:contextValue.challenge_id,
  registration_challenge_nonce_sha256:contextValue.challenge_nonce_sha256,original_admission_intent_sha256:intentHash,
  withdrawal_operation_id:U(id*100+10),withdrawal_challenge_id:U(id*100+11),withdrawal_challenge_nonce_sha256:H(id*100+12)});
 const q=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
 const r=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
 const z=BigInt('0x'+await digest('DJC-CORE-INSTALL-PRINCIPAL-POSSESSION-CANDIDATE-V1\n'+body));
 const sighex=r.toString(16).padStart(64,'0')+((z+r)%q).toString(16).padStart(64,'0');
 const signature=btoa(String.fromCharCode(...sighex.match(/../g)!.map(v=>parseInt(v,16)))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
 const chain={generation,receipt,subject,context,proof,original_expected_transcript:body};
 return {chain,intent,withdrawal,body,signature,proofHash,intentHash,identity:contextValue.registry_identity_sha256,
  restore:contextValue.registry_restore_policy_sha256,operation:contextValue.registration_operation_id,
  withdrawalOperation:JSON.parse(withdrawal).withdrawal_operation_id as string,
  prepare:{...chain,intent},admit:{...chain,intent,proof_body:body,signature_b64url:signature,accepted_independent_authority_bundle_sha256:H(999)},
  withdraw:{...chain,intent,withdrawal}};
}
