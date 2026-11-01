/** Source-only Apple cryptographic evidence kernel, no DB/native admission.
 * No caller root, QA APP/build/environment, boolean status supplier or SDK call.
 * Apple protocol/path/nonce checks do NOT assert attestation-chain revocation.
 * Receipt common-certificate currentness is separately checked with actual
 * signed CRL/OCSP at code-pinned Apple endpoints, without absent-status bypass.
 */
import cbor from 'cbor';
import * as asn from 'asn1js';
import * as pki from 'pkijs';
import {prepareCommonStatusRequest,qualifyCommonStatus} from '../../qualification/rendezvous/receipt-status-candidate.mjs';
const asn1js=asn;
export class NativeAppleProofRejected extends Error {}
export class NativeReceiptStatusUnavailable extends Error {}
const need=v=>{if(!v)throw new NativeAppleProofRejected('native_apple_proof_rejected');};
const fromB64=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0));
const toB64=v=>btoa(String.fromCharCode(...v));
const bytes=value=>new Uint8Array(value);
const same=(a,b)=>{a=bytes(a);b=bytes(b);return a.length===b.length&&a.every((v,i)=>v===b[i]);};
const hash=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',Uint8Array.from(v)));
const raw=n=>new Uint8Array(n.toSchema().toBER(false));
const concat=(a,b)=>{const v=new Uint8Array(a.length+b.length);v.set(a);v.set(b,a.length);return v;};
const bounded=(v,min,max)=>{need(v instanceof Uint8Array&&v.length>=min&&v.length<=max);return v;};
function parseCall(operation){try{return operation();}catch(error){if(error instanceof NativeAppleProofRejected)throw error;throw new NativeAppleProofRejected('native_apple_encoding_rejected');}}
async function checkedPki(state,work){try{return await work();}finally{state.check();}}
function guardedEngine(window,malformedKeyMayReject=false){
 let failure;
 const subtle=new Proxy(crypto.subtle,{get(target,key){const method=Reflect.get(target,key,target);if(typeof method!=='function')return method;
  return async(...args)=>{try{return await window.run(()=>Reflect.apply(method,target,args));}catch(error){
   // An untrusted certificate's off-curve SPKI is malformed proof. Fixed
   // algorithm/subtle failures and cancellation retain their original cause.
   if(!(malformedKeyMayReject&&key==='importKey'&&error?.name==='DataError'))failure??=error;throw error;
  }};
 }});
 return {engine:new pki.CryptoEngine({name:'host-wake-apple-evidence',crypto:{subtle},subtle}),check(){window.check();if(failure)throw failure;}};
}
const APPLE_ATTEST_ROOT_B64='MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD';
const APPLE_RECEIPT_ROOT_B64='MIICQzCCAcmgAwIBAgIILcX8iNLFS5UwCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTQwNDMwMTgxOTA2WhcNMzkwNDMwMTgxOTA2WjBnMRswGQYDVQQDDBJBcHBsZSBSb290IENBIC0gRzMxJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABJjpLz1AcqTtkyJygRMc3RCV8cWjTnHcFBbZDuWmBSp3ZHtfTjjTuxxEtX/1H7YyYl3J6YRbTzBPEVoA/VhYDKX1DyxNB0cTddqXl5dvMVztK517IDvYuVTZXpmkOlEKMaNCMEAwHQYDVR0OBBYEFLuw3qFYM4iapIqZ3r6966/ayySrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQCD6cHEFl4aXTQY2e3v9GwOAEZLuN+yRhHFD/3meoyhpmvOwgPUnPWTxnS4at+qIxUCMG1mihDK1A3UT82NQz60imOlM27jbdoXt2QfyFMm+YhidDkLF1vLUagM6BgD56KyKA==';
const PATH_OID = {
  bc: '2.5.29.19', ku: '2.5.29.15', eku: '2.5.29.37', ski: '2.5.29.14', aki: '2.5.29.35',
  nonce: '1.2.840.113635.100.8.2', appEku: '1.2.840.113635.100.4.24',
};
const requireValue=need;
function appCertificate(encoded) {
  requireValue(encoded instanceof Uint8Array && encoded.length > 0 && encoded.length <= 8192);
  const decoded = asn1js.fromBER(encoded);
  requireValue(decoded.offset === encoded.length && !decoded.result.error);
  const result = new pki.Certificate({ schema: decoded.result });
  requireValue(same(result.toSchema().toBER(false), encoded));
  return result;
}
function appExtensions(cert, leaf) {
  const result = new Map();
  const allowed = new Set([PATH_OID.bc, PATH_OID.ku, PATH_OID.ski, PATH_OID.aki,
    ...(leaf ? [PATH_OID.eku, PATH_OID.nonce, '1.2.840.113635.100.8.5', '1.2.840.113635.100.8.6', '1.2.840.113635.100.8.7'] : [])]);
  for (const extension of cert.extensions ?? []) {
    requireValue(!result.has(extension.extnID) && allowed.has(extension.extnID));
    // Closed measured certificate profile: only BC and KU may be critical.
    requireValue(!extension.critical || [PATH_OID.bc, PATH_OID.ku].includes(extension.extnID));
    result.set(extension.extnID, extension);
  }
  return result;
}
function appExtension(map, oid, critical) {
  const value = map.get(oid);
  requireValue(value && Boolean(value.critical) === critical);
  return value;
}
function appSki(map) {
  const value = appExtension(map, PATH_OID.ski, false).parsedValue;
  requireValue(value instanceof asn1js.OctetString && value.valueBlock.valueHexView.length > 0);
  return value.valueBlock.valueHexView;
}
function appAkiMatches(map, issuerSki, optional) {
  if (!map.has(PATH_OID.aki)) { requireValue(optional); return; }
  const value = appExtension(map, PATH_OID.aki, false).parsedValue;
  requireValue(value instanceof pki.AuthorityKeyIdentifier && value.keyIdentifier &&
    !value.authorityCertIssuer && !value.authorityCertSerialNumber &&
    same(value.keyIdentifier.valueBlock.valueHexView, issuerSki));
}
function appShape(cert, map, leaf, intermediatesBelow) {
  const serial = cert.serialNumber.valueBlock.valueHexView;
  requireValue(cert.version === 2 && serial.length > 0 && serial.length <= 20 && !(serial[0] & 0x80) &&
    serial.some(value => value !== 0) && !(serial.length > 1 && serial[0] === 0 && serial[1] < 0x80));
  requireValue(cert.signatureValue.valueBlock.unusedBits === 0 && cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.unusedBits === 0);
  const basic = appExtension(map, PATH_OID.bc, true).parsedValue;
  const usage = appExtension(map, PATH_OID.ku, true).parsedValue;
  requireValue(basic instanceof pki.BasicConstraints && Boolean(basic.cA) === !leaf);
  if (leaf) requireValue(basic.pathLenConstraint === undefined);
  requireValue(usage instanceof asn1js.BitString && usage.valueBlock.valueHexView.length > 0);
  const flags = usage.valueBlock.valueHexView[0];
  requireValue(leaf ? Boolean(flags & 0x80) && !(flags & 0x04) : Boolean(flags & 0x04));
  if (basic.pathLenConstraint !== undefined) {
    requireValue(Number.isInteger(basic.pathLenConstraint) && basic.pathLenConstraint >= intermediatesBelow);
  }
  // Measured Apple ECDSA profile; no SHA1/RSA/unknown algorithm fallback.
  requireValue(cert.signatureAlgorithm.algorithmId === cert.signature.algorithmId &&
    ['1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3'].includes(cert.signatureAlgorithm.algorithmId) &&
    !cert.signatureAlgorithm.algorithmParams && !cert.signature.algorithmParams);
  if (leaf) {
    requireValue(cert.subjectPublicKeyInfo.algorithm.algorithmId === '1.2.840.10045.2.1' &&
      cert.subjectPublicKeyInfo.algorithm.algorithmParams instanceof asn1js.ObjectIdentifier &&
      cert.subjectPublicKeyInfo.algorithm.algorithmParams.valueBlock.toString() === '1.2.840.10045.3.1.7');
    const point = cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
    requireValue(point.length === 65 && point[0] === 4);
    const eku = appExtension(map, PATH_OID.eku, false).parsedValue;
    requireValue(eku instanceof pki.ExtKeyUsage && eku.keyPurposes.length === 1 && eku.keyPurposes[0] === PATH_OID.appEku);
    appExtension(map, PATH_OID.nonce, false); // Value/challenge checked by the separate composed verifier.
  }
}

async function appPath(leafBytes,intermediateBytes,window){
 const rootBytes=fromB64(APPLE_ATTEST_ROOT_B64),now=window.check();
 const leaf=parseCall(()=>appCertificate(leafBytes)),intermediate=parseCall(()=>appCertificate(intermediateBytes)),root=parseCall(()=>appCertificate(rootBytes));
 const le=appExtensions(leaf,true),ie=appExtensions(intermediate,false),re=appExtensions(root,false);
 appShape(leaf,le,true,0);appShape(intermediate,ie,false,0);appShape(root,re,false,1);
 appAkiMatches(re,appSki(re),true);appAkiMatches(ie,appSki(re),false);appAkiMatches(le,appSki(ie),true);
 need(root.subject.isEqual(root.issuer)&&intermediate.issuer.isEqual(root.subject)&&leaf.issuer.isEqual(intermediate.subject));
 for(const cert of [leaf,intermediate,root])need(now>=cert.notBefore.value.getTime()&&now<cert.notAfter.value.getTime());
 const importCheck=guardedEngine(window,true);let publicKey;try{publicKey=await leaf.getPublicKey(undefined,importCheck.engine);}catch(error){importCheck.check();if(error?.name==='DataError')throw new NativeAppleProofRejected();throw error;}importCheck.check();
 const checked=guardedEngine(window),engine=checked.engine;
 need(publicKey.type==='public'&&publicKey.algorithm.name==='ECDSA'&&publicKey.algorithm.namedCurve==='P-256');
 const rootValid=await checkedPki(checked,()=>root.verify(root,engine));need(rootValid);
 const path=await checkedPki(checked,()=>new pki.CertificateChainValidationEngine({trustedCerts:[root],certs:[intermediate,leaf],checkDate:new Date(now)}).verify({passedWhenNotRevValues:false},engine));
 need(path.result===true&&path.certificatePath?.length===3);
 for(const [i,expected] of [leafBytes,intermediateBytes,rootBytes].entries())need(same(raw(path.certificatePath[i]),expected));
 return {leaf,expires:Math.min(...[leaf,intermediate,root].map(c=>c.notAfter.value.getTime())),scope:'APPLE_APPATTEST_PROTOCOL_PATH_VALIDITY_ONLY_NO_REVOCATION_ASSERTION'};
}
const OID = { bc:'2.5.29.19', ku:'2.5.29.15', ski:'2.5.29.14', aki:'2.5.29.35',
  leaf:'1.2.840.113635.100.12.15', inter:'1.2.840.113635.100.6.2.3',
  sha256:'2.16.840.1.101.3.4.2.1', ec256:'1.2.840.10045.4.3.2', ec384:'1.2.840.10045.4.3.3' };
function parse(bytes,max=16384,ber=false) {
  bounded(bytes,1,max);
  const result=asn.fromBER(bytes,{maxDepth:24,maxNodes:2048,maxContentLength:max,parseEmbedded:false});
  need(result.offset===bytes.length&&!result.result.error);
  const indefinite = new Set(['','/1','/1/0','/1/0/2','/1/0/2/1','/1/0/2/1/0','/1/0/3']);
  function inspect(n,path) {
    need(n.idBlock.blockLength===1);
    if(n.lenBlock.isIndefiniteForm) need(ber&&indefinite.has(path)&&n.idBlock.isConstructed);
    else {
      let size=n.lenBlock.length, expected=1;
      if(size>=128){expected++;while(size>=256){expected++;size=Math.floor(size/256);}}
      need(n.lenBlock.blockLength===expected);
    }
    if(n instanceof asn.Integer){ const v=n.valueBlock.valueHexView;
      need(v.length>0 && !(v.length>1&&((v[0]===0&&v[1]<128)||(v[0]===255&&v[1]>=128)))); }
    if(n.idBlock.isConstructed) n.valueBlock.value.forEach((v,i)=>inspect(v,path+'/'+i));
  }
  inspect(result.result,'');return result.result;
}
function seq(n,count){need(n instanceof asn.Sequence&&n.valueBlock.value.length===count);return n.valueBlock.value;}
function context(n,tag,count){need(n instanceof asn.Constructed&&n.idBlock.tagClass===3&&n.idBlock.tagNumber===tag&&n.valueBlock.value.length===count);return n.valueBlock.value;}
function algorithm(v,oid){need(v.algorithmId===oid&&!v.algorithmParams);}
function digest(v){need(v.algorithmId===OID.sha256&&(!v.algorithmParams||v.algorithmParams instanceof asn.Null));}
function ext(cert,role){
  const map=new Map();
  const permitted=role==='leaf'?[OID.leaf,'1.3.6.1.5.5.7.1.1','2.5.29.32']:role==='inter'?[OID.inter,'1.3.6.1.5.5.7.1.1','2.5.29.31']:[];
  const allowed=new Set([OID.bc,OID.ku,OID.ski,OID.aki,...permitted]);
  for(const e of cert.extensions??[]){need(!map.has(e.extnID)&&allowed.has(e.extnID)&&(!e.critical||[OID.bc,OID.ku].includes(e.extnID)));map.set(e.extnID,e);}
  const get=(id,critical)=>{const e=map.get(id);need(e&&Boolean(e.critical)===critical);return e;};
  const bc=get(OID.bc,true).parsedValue, ku=get(OID.ku,true).parsedValue;
  need(bc instanceof pki.BasicConstraints&&Boolean(bc.cA)===(role!=='leaf'));
  need(ku instanceof asn.BitString&&ku.valueBlock.valueHexView.length>0);
  const flags=ku.valueBlock.valueHexView[0];
  if(role==='leaf')need(Boolean(flags&128)&&!(flags&4)&&bc.pathLenConstraint===undefined);
  else {need(Boolean(flags&4));if(bc.pathLenConstraint!==undefined)need(Number.isInteger(bc.pathLenConstraint)&&bc.pathLenConstraint>=(role==='root'?1:0));}
  const ski=get(OID.ski,false).parsedValue;need(ski instanceof asn.OctetString&&!ski.idBlock.isConstructed&&ski.valueBlock.valueHexView.length>0);
  if(role!=='root')need(same(get(OID[role],false).extnValue.valueBlock.valueHexView,new Uint8Array([5,0])));
  return {map,ski:ski.valueBlock.valueHexView};
}
function aki(info,issuer,optional=false){
  if(!info.map.has(OID.aki)){need(optional);return;}
  const e=info.map.get(OID.aki),v=e.parsedValue;
  need(!e.critical&&v instanceof pki.AuthorityKeyIdentifier&&v.keyIdentifier&&!v.authorityCertIssuer&&!v.authorityCertSerialNumber&&same(v.keyIdentifier.valueBlock.valueHexView,issuer.ski));
}
function certShape(cert,role,now){
  const serial=cert.serialNumber.valueBlock.valueHexView;
  need(cert.version===2&&serial.length>0&&serial.length<=20&&!(serial[0]&128)&&serial.some(v=>v!==0));
  need(cert.signatureValue.valueBlock.unusedBits===0&&cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.unusedBits===0);
  const sig=role==='leaf'?OID.ec256:OID.ec384;
  algorithm(cert.signature,sig);algorithm(cert.signatureAlgorithm,sig);
  const key=cert.subjectPublicKeyInfo.algorithm;
  need(key.algorithmId==='1.2.840.10045.2.1'&&key.algorithmParams instanceof asn.ObjectIdentifier&&
    key.algorithmParams.valueBlock.toString()===(role==='root'?'1.3.132.0.34':'1.2.840.10045.3.1.7'));
  const point=cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
  need(point[0]===4&&point.length===(role==='root'?97:65));
  need(now>=cert.notBefore.value.getTime()&&now<cert.notAfter.value.getTime());
}
function signature(bytes){
  bounded(bytes,8,72);need(bytes[0]===48&&bytes[1]===bytes.length-2);
  const parts=seq(parse(bytes,72),2);
  for(const n of parts){need(n instanceof asn.Integer&&!n.idBlock.isConstructed);const v=n.valueBlock.valueHexView;need(v.length>0&&v.length<=33&&!(v[0]&128)&&v.some(x=>x!==0)&&(v.length<33||v[0]===0));}
}
function payloadFields(bytes){
  const set=parse(bytes,8192);need(set instanceof asn.Set&&set.valueBlock.value.length===8);
  const fields=new Map(),expected=new Set([2,3,4,5,6,7,12,21]);
  for(const item of set.valueBlock.value){const [type,version,value]=seq(item,3);
    need(type instanceof asn.Integer&&version instanceof asn.Integer&&value instanceof asn.OctetString&&!value.idBlock.isConstructed);
    const id=type.valueBlock.valueDec;need(expected.has(id)&&!fields.has(id)&&version.valueBlock.valueDec===1);
    fields.set(id,value.valueBlock.valueHexView);
  }
  return fields;
}
function instant(bytes){
  const text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  need(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text));
  const n=Date.parse(text);need(Number.isSafeInteger(n)&&new Date(n).toISOString()===text);return n;
}

async function readStatusResponse(response,window,signal){
 const length=response.headers.get('content-length');if(length!==null&&(!/^(0|[1-9][0-9]*)$/.test(length)||Number(length)>65536))throw new NativeReceiptStatusUnavailable();
 if(!response.body)throw new NativeReceiptStatusUnavailable();const reader=response.body.getReader(),parts=[];let size=0;
 try{for(;;){const part=await window.run(()=>reader.read(),signal);if(part.done)break;size+=part.value.length;if(size>65536)throw new NativeReceiptStatusUnavailable();parts.push(part.value);}if(!size)throw new NativeReceiptStatusUnavailable();}
 finally{void reader.cancel().catch(()=>{});reader.releaseLock();}
 const out=new Uint8Array(size);let at=0;for(const p of parts){out.set(p,at);at+=p.length;}return out;
}
async function commonStatus(kind,cert,issuer,root,window,fetcher){
 const request=await window.run(()=>prepareCommonStatusRequest(kind,cert,issuer,root));
 const expected=kind==='crl'?{role:'issuer-crl',url:'http://crl.apple.com/applerootcag3.crl',mime:'application/pkix-crl',method:'GET'}:{role:'signer-ocsp',url:'http://ocsp.apple.com/ocsp03-aaica5g101',mime:'application/ocsp-response',method:'POST'};
 if(!request||request.role!==expected.role||request.url!==expected.url||request.accept!==expected.mime||request.method!==expected.method)throw new NativeReceiptStatusUnavailable();
 const stage=new AbortController(),timer=setTimeout(()=>stage.abort(),4000),signal=AbortSignal.any([window.signal,stage.signal]);
 try{
  const response=await window.run(()=>fetcher(expected.url,{method:expected.method,body:request.body,headers:{accept:expected.mime,...(kind==='ocsp'?{'content-type':'application/ocsp-request'}:{})},redirect:'manual',credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store',signal}),signal);
  if(response.status!==200||response.redirected||response.headers.get('content-type')?.split(';')[0].trim().toLowerCase()!==expected.mime)throw new NativeReceiptStatusUnavailable();
  const raw=await readStatusResponse(response,window,signal),status=await window.run(()=>qualifyCommonStatus(kind,raw,cert,issuer,root),signal);
  if(!status||window.check()<status.checkedAt||window.check()>=status.cacheUntil)throw new NativeReceiptStatusUnavailable();return {raw,status};
 }finally{clearTimeout(timer);stage.abort();}
}
async function receiptEvidence(encoded,attestedCert,clientData,policy,window,fetcher){
  const anchor=fromB64(APPLE_RECEIPT_ROOT_B64),now=window.check();
  bounded(attestedCert,1,8192);bounded(clientData,1,8192);bounded(anchor,1,8192);need(Number.isSafeInteger(now));
  const outer=parseCall(()=>parse(encoded,16384,true)),[contentType,wrapped]=seq(outer,2);
  need(contentType instanceof asn.ObjectIdentifier&&contentType.valueBlock.toString()===pki.ContentInfo.SIGNED_DATA);
  const sdNode=context(wrapped,0,1)[0],nodes=seq(sdNode,5);
  need(nodes[0] instanceof asn.Integer&&nodes[0].valueBlock.valueDec===1);
  need(nodes[1] instanceof asn.Set&&nodes[1].valueBlock.value.length===1);
  const ec=seq(nodes[2],2);need(ec[0] instanceof asn.ObjectIdentifier&&ec[0].valueBlock.toString()===pki.ContentInfo.DATA);
  const octet=context(ec[1],0,1)[0];need(octet instanceof asn.OctetString);
  if(octet.idBlock.isConstructed)need(octet.valueBlock.value.length>0&&octet.valueBlock.value.length<=8&&octet.valueBlock.value.every(v=>v instanceof asn.OctetString&&!v.idBlock.isConstructed));
  const body=new Uint8Array(octet.getValue());bounded(body,1,8192);
  const certificates=context(nodes[3],0,3);
  for(const cert of certificates)parse(new Uint8Array(cert.toBER(false)),8192);
  need(nodes[4] instanceof asn.Set&&nodes[4].valueBlock.value.length===1);seq(nodes[4].valueBlock.value[0],5); // No signed/unsigned attrs in measured profile.
  const sd=parseCall(()=>new pki.SignedData({schema:sdNode}));
  need(sd.version===1&&sd.signerInfos.length===1&&sd.certificates?.length===3&&!sd.crls&&!sd.ocsps);
  digest(sd.digestAlgorithms[0]);const si=sd.signerInfos[0];need(si.version===1&&si.sid instanceof pki.IssuerAndSerialNumber&&!si.signedAttrs&&!si.unsignedAttrs);
  digest(si.digestAlgorithm);algorithm(si.signatureAlgorithm,OID.ec256);signature(si.signature.valueBlock.valueHexView);
  need(sd.certificates.every(c=>c instanceof pki.Certificate));
  const root=parseCall(()=>new pki.Certificate({schema:parse(anchor,8192)}));
  const roots=sd.certificates.filter(c=>same(raw(c),anchor));need(roots.length===1);
  const signers=sd.certificates.filter(c=>c.issuer.isEqual(si.sid.issuer)&&c.serialNumber.isEqual(si.sid.serialNumber));need(signers.length===1);
  const leaf=signers[0],others=sd.certificates.filter(c=>c!==leaf&&c!==roots[0]);need(leaf!==roots[0]&&others.length===1);const inter=others[0];
  certShape(root,'root',now);certShape(inter,'inter',now);certShape(leaf,'leaf',now);
  const ri=ext(root,'root'),ii=ext(inter,'inter'),li=ext(leaf,'leaf');aki(ri,ri,true);aki(ii,ri);aki(li,ii); // No missing leaf AKI exception for receipts.
  need(root.subject.isEqual(root.issuer)&&inter.issuer.isEqual(root.subject)&&leaf.issuer.isEqual(inter.subject));
  const checked=guardedEngine(window),engine=checked.engine;
  need(await checkedPki(checked,()=>root.verify(root,engine))&&await checkedPki(checked,()=>inter.verify(root,engine))&&await checkedPki(checked,()=>leaf.verify(inter,engine)));
  const verified=await checkedPki(checked,()=>sd.verify({signer:0,checkChain:false,extendedMode:true},engine));
  need(verified.signatureVerified===true&&verified.signerCertificate&&same(raw(verified.signerCertificate),raw(leaf)));
  const fields=payloadFields(body);
  need(same(fields.get(2),new TextEncoder().encode(policy.app_identifier))&&same(fields.get(3),attestedCert)&&same(fields.get(4),await hash(clientData)));
  need(same(fields.get(6),new TextEncoder().encode('ATTEST'))&&same(fields.get(7),new TextEncoder().encode(policy.app_attest_environment==='development'?'sandbox':'production')));
  bounded(fields.get(5),1,1024);const created=instant(fields.get(12)),expires=instant(fields.get(21));need(expires>created);

  need(now>=created&&now-created<=300000&&now<expires);
  const [issuerStatus,signerStatus]=await Promise.all([
   commonStatus('crl',raw(inter),anchor,anchor,window,fetcher),
   commonStatus('ocsp',raw(leaf),raw(inter),anchor,window,fetcher)
  ]);
  const crl=parseCall(()=>new pki.CertificateRevocationList({schema:parse(issuerStatus.raw,65536)}));
  const ocsp=parseCall(()=>new pki.OCSPResponse({schema:parse(signerStatus.raw,65536)}));
  need(ocsp.responseBytes);const basic=parseCall(()=>new pki.BasicOCSPResponse({schema:parse(ocsp.responseBytes.response.valueBlock.valueHexView,65536)}));
  const path=await checkedPki(checked,()=>new pki.CertificateChainValidationEngine({trustedCerts:[root],certs:[inter,leaf],crls:[crl],ocsps:[basic],checkDate:new Date(window.check())}).verify({passedWhenNotRevValues:false},engine));
  if(path.result!==true||path.certificatePath?.length!==3)throw new NativeReceiptStatusUnavailable();
  for(const [i,c] of [leaf,inter,root].entries())if(!same(raw(path.certificatePath[i]),raw(c)))throw new NativeReceiptStatusUnavailable();
  const after=window.check();need(after>=created&&after-created<=300000&&after<expires);
  const certificateExpiresAt=Math.min(...[leaf,inter,root].map(c=>c.notAfter.value.getTime()));need(after<certificateExpiresAt);
  return {created,expires,receipt:encoded.slice(),certificateExpiresAt,statusCheckedAt:Math.max(issuerStatus.status.checkedAt,signerStatus.status.checkedAt),statusExpiresAt:Math.min(issuerStatus.status.cacheUntil,signerStatus.status.cacheUntil),scope:'APPLE_RECEIPT_SIGNATURE_PATH_FIELDS_AND_FRESH_SIGNED_COMMON_STATUS_ONLY_NO_ENROLLMENT'};
}

function decodeCbor(encoded,extended=false){return parseCall(()=>cbor.decodeFirstSync(Buffer.from(encoded),{preventDuplicateKeys:true,preferMap:true,max_depth:8,extendedResults:extended}));}
function closedMap(value,keys){need(value instanceof Map&&value.size===keys.length&&keys.every(k=>value.has(k)));return value;}
/** Raw Apple evidence only. The trusted TS caller supplies its actual saved
 * policy/job; only its separate opaque receipt/atomic D1 writer may enroll. */
export async function verifyAppleAttestationEvidence(encoded,clientData,keyId,policy,window,fetcher){
 try{
  window.check();bounded(encoded,1,9216);bounded(clientData,1,8192);need(policy.profile==='host_wake_apple_properties_attestation_v2'&&(policy.app_attest_environment==='development'||policy.app_attest_environment==='production')&&typeof policy.app_identifier==='string'&&typeof policy.bundle_version==='string');
  const categoryPolicy=fromB64(policy.launch_validation_category_b64);need(categoryPolicy.length===4&&toB64(categoryPolicy)===policy.launch_validation_category_b64&&[2,3,4,5].includes(new DataView(categoryPolicy.buffer).getUint32(0,true)));
  const credential=fromB64(keyId);need(credential.length===32&&toB64(credential)===keyId);
  const obj=closedMap(decodeCbor(encoded),['fmt','attStmt','authData']);need(obj.get('fmt')==='apple-appattest');
  const statement=closedMap(obj.get('attStmt'),['x5c','receipt']),chain=statement.get('x5c');need(Array.isArray(chain)&&chain.length===2);
  const [leafBytes,interBytes]=chain.map(v=>bounded(v,1,8192)),receiptBytes=bounded(statement.get('receipt'),1,16384);
  const path=await appPath(leafBytes,interBytes,window),auth=bounded(obj.get('authData'),88,2048);
  need(auth[32]===0xc0&&same(auth.subarray(0,32),await hash(new TextEncoder().encode(policy.app_identifier))));
  need(new DataView(auth.buffer,auth.byteOffset,auth.byteLength).getUint32(33,false)===0);
  const aaguid=policy.app_attest_environment==='development'?new TextEncoder().encode('appattestdevelop'):concat(new TextEncoder().encode('appattest'),new Uint8Array(7));
  need(same(auth.subarray(37,53),aaguid)&&new DataView(auth.buffer,auth.byteOffset,auth.byteLength).getUint16(53,false)===32&&same(auth.subarray(55,87),credential));
  const decoded=decodeCbor(auth.subarray(87),true),cose=closedMap(decoded.value,[1,3,-1,-2,-3]);need(cose.get(1)===2&&cose.get(3)===-7&&cose.get(-1)===1);
  const point=concat(new Uint8Array([4]),concat(bounded(cose.get(-2),32,32),bounded(cose.get(-3),32,32)));
  const props=closedMap(decodeCbor(bounded(decoded.unused,1,1024)),['apple_bundle_version_01','apple_validation_category_01']);
  need(props.get('apple_bundle_version_01')===policy.bundle_version&&same(bounded(props.get('apple_validation_category_01'),4,4),fromB64(policy.launch_validation_category_b64)));
  const leaf=path.leaf;need(same(point,leaf.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView)&&same(await hash(point),credential));
  const found=leaf.extensions.filter(e=>e.extnID===PATH_OID.nonce);need(found.length===1&&!found[0].critical);
  const expected=await hash(concat(auth,await hash(clientData))),nonce=new asn.Sequence({value:[new asn.Constructed({idBlock:{tagClass:3,tagNumber:1},value:[new asn.OctetString({valueHex:expected})]})]});
  need(same(new Uint8Array(nonce.toBER(false)),found[0].extnValue.valueBlock.valueHexView));
  const receipt=await receiptEvidence(receiptBytes,leafBytes,clientData,policy,window,fetcher);window.check();need(window.check()<path.expires);
  return {scope:'APPLE_ATTESTATION_AND_RECEIPT_CRYPTO_STATUS_ONLY_NO_ENROLLMENT',public_key_spki_b64:toB64(new Uint8Array(leaf.subjectPublicKeyInfo.toSchema().toBER(false))),receipt:receipt.receipt,receiptCreated:receipt.created,expires:Math.min(path.expires,receipt.certificateExpiresAt,receipt.expires),attestationPathScope:path.scope,receiptScope:receipt.scope,statusCheckedAt:receipt.statusCheckedAt,statusExpiresAt:receipt.statusExpiresAt};
 }catch(error){window.check();if(error instanceof NativeAppleProofRejected)return null;throw error;}
}
