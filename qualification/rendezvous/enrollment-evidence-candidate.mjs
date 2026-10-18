// LOCAL QUALIFICATION ONLY. No key persistence, public endpoint, native-wire or enrollment GO.
import {qualifyAttestationCore} from './app-attest-core-candidate.mjs';
import {qualifyFreshReceiptEvidence} from './receipt-cms-candidate.mjs';
import {CommonStatusClient} from './receipt-status-client.mjs';
import {attestationRoot,receiptRoot} from 'djc-enrollment-trust';

const POLICY='ios-dev-qualification/1';
const need=v=>{if(!v)throw new Error('enrollment_rejected');};
const integer=v=>Number.isSafeInteger(v)&&v>=0;
// Buffer.slice() is a view. Always own a plain Uint8Array before asynchronous work.
const copy=(v,max)=>{need(v instanceof Uint8Array&&v.length>0&&v.length<=max);return Uint8Array.from(v);};
const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const closed=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===keys.sort().join(','));
function opaque(v){need(typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v));const b=atob(v.replaceAll('-','+').replaceAll('_','/'));need(b.length===32&&btoa(b).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')===v);}
function keyId(v){need(typeof v==='string'&&/^[A-Za-z0-9+/]{43}=$/.test(v));const b=atob(v);need(b.length===32&&btoa(b)===v);}
function snapshot(readState,nonceOnly=false){
  const state=readState();closed(state,['policy','challenge']);
  closed(state.policy,['id','revision','enabled','expiresAt']);
  closed(state.challenge,['id','keyId','action','createdAt','expiresAt','clientData']);
  const policy={...state.policy},challenge={...state.challenge,clientData:copy(state.challenge.clientData,2048)};
  // Existing registration wire hashes the decoded 32-byte server nonce, never JSON clientData.
  need(!nonceOnly||challenge.clientData.length===32);
  need(policy.id===POLICY&&policy.enabled===true&&typeof policy.revision==='string'&&policy.revision.length>0&&policy.revision.length<=128&&integer(policy.expiresAt));
  opaque(challenge.id);keyId(challenge.keyId);need(challenge.action==='register'&&integer(challenge.createdAt)&&integer(challenge.expiresAt)&&challenge.expiresAt>challenge.createdAt&&challenge.expiresAt-challenge.createdAt<=120000);
  return {policy,challenge};
}
function current(readState,initial,nonceOnly){
  const state=snapshot(readState,nonceOnly),now=Date.now();need(integer(now)&&now>=initial.challenge.createdAt&&now<initial.challenge.expiresAt&&now<state.policy.expiresAt);
  for(const name of ['id','revision','enabled','expiresAt'])need(state.policy[name]===initial.policy[name]);
  for(const name of ['id','keyId','action','createdAt','expiresAt'])need(state.challenge[name]===initial.challenge[name]);
  need(same(state.challenge.clientData,initial.challenge.clientData));return now;
}
function receiptTime(receipt,now){need(receipt.fresh===true&&integer(receipt.created)&&integer(receipt.expires)&&receipt.expires>receipt.created&&now>=receipt.created&&now-receipt.created<=300000&&now<receipt.expires);}
function statusTime(status,kind,now){
  need(status?.ok===true&&status.scope===(kind==='crl'?'COMMON_RECEIPT_ISSUER_CRL_NOT_LISTED_ONLY_NO_ENROLLMENT':'COMMON_RECEIPT_OCSP_GOOD_ONLY_NO_ENROLLMENT'));
  need(['checkedAt','cacheUntil','thisUpdate','nextUpdate'].every(k=>integer(status[k]))&&status.thisUpdate<=status.checkedAt&&status.checkedAt<=now&&now<status.cacheUntil&&status.cacheUntil<=status.nextUpdate&&status.cacheUntil<=status.checkedAt+3600000);
  if(kind==='ocsp')need(now-status.thisUpdate<=86400000&&status.cacheUntil<=status.thisUpdate+86400000);
}
const savedStatus=value=>value&&Object.fromEntries(['ok','scope','checkedAt','cacheUntil','thisUpdate','nextUpdate'].map(k=>[k,value[k]]));
function engine(readState,components,scope,nonceOnly){
  // Private closure; one active call per instance. Not an aggregate ingress or CPU budget.
  let busy=false;
  const roots={attestation:copy(attestationRoot,8192),receipt:copy(receiptRoot,8192)};
  return Object.freeze({async verify(request){
    if(busy)return {ok:false,error:'enrollment_rejected'};busy=true;
    try{
      closed(request,['challengeId','keyId','attestation']);
      const proof=copy(request.attestation,32768),id=request.challengeId,key=request.keyId;
      opaque(id);keyId(key);const initial=snapshot(readState,nonceOnly);let cryptoDeadline=Infinity;
      const check=()=>{const now=current(readState,initial,nonceOnly);need(now<cryptoDeadline);return now;};check();
      need(id===initial.challenge.id&&key===initial.challenge.keyId);
      const core=await components.core(proof,initial.challenge.clientData.slice(),key,roots.attestation.slice());let now=check();
      need(core?.scope==='ATTESTATION_CORE_ONLY_RECEIPT_UNVERIFIED_NO_ENROLLMENT');
      const attestationExpiresAt=core.certificateExpiresAt;need(integer(attestationExpiresAt)&&now<attestationExpiresAt);cryptoDeadline=attestationExpiresAt;
      const point=copy(core.point,65),receipt=copy(core.receipt,16384),leaf=copy(core.attestedLeaf,8192);need(point.length===65&&point[0]===4);
      const pointDigest=new Uint8Array(await crypto.subtle.digest('SHA-256',point));check();need(btoa(String.fromCharCode(...pointDigest))===key);
      const result=await components.cms(receipt.slice(),leaf,initial.challenge.clientData.slice(),roots.receipt.slice());now=check();
      need(result?.scope==='CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT');
      const cms={fresh:result.fresh,created:result.created,expires:result.expires,certificateExpiresAt:result.certificateExpiresAt};receiptTime(cms,now);need(integer(cms.certificateExpiresAt));cryptoDeadline=Math.min(cryptoDeadline,cms.certificateExpiresAt);check();
      const certs={signer:copy(result.signer,8192),issuer:copy(result.issuer,8192),root:copy(result.root,8192)};need(same(certs.root,roots.receipt));
      // Only common CMS-authenticated certificates go to the fixed status client. Never the private leaf/receipt/nonce/key.
      const issuer=savedStatus(await components.status.check('crl',certs.issuer.slice(),certs.root.slice(),certs.root.slice()));now=check();receiptTime(cms,now);statusTime(issuer,'crl',now);
      const signer=savedStatus(await components.status.check('ocsp',certs.signer.slice(),certs.issuer.slice(),certs.root.slice()));now=check();
      receiptTime(cms,now);statusTime(issuer,'crl',now);statusTime(signer,'ocsp',now);need(now<attestationExpiresAt&&now<cms.certificateExpiresAt);
      return {ok:true,evidence:{scope,keyId:key,challengeId:id,challengeCreatedAt:initial.challenge.createdAt,challengeExpiresAt:initial.challenge.expiresAt,
        policy:POLICY,policyRevision:initial.policy.revision,verifiedAt:now,validUntil:Math.min(initial.challenge.expiresAt,initial.policy.expiresAt,cms.created+300001,cms.expires,attestationExpiresAt,cms.certificateExpiresAt,issuer.cacheUntil,signer.cacheUntil),
        publicPoint:point,initialReceipt:receipt,receiptCreatedAt:cms.created}};
    }catch{return {ok:false,error:'enrollment_rejected'};}finally{busy=false;}
  }});
}
export function createEnrollmentEvidenceVerifier(readState){
  return engine(readState,{core:qualifyAttestationCore,cms:qualifyFreshReceiptEvidence,status:new CommonStatusClient()},'COMPOSED_PRIVATE_EVIDENCE_ONLY_NO_ATOMIC_REGISTRATION',true);
}
// Explicit orchestration-only fixture path. It is never selected by the default factory or a request.
export function createSoftwareStubEnrollmentVerifier(readState,components){
  return engine(readState,components,'SOFTWARE_STUB_COMPOSITION_ONLY_NOT_CRYPTO_OR_ENROLLMENT_PROOF',false);
}
