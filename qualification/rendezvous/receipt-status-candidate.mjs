// ISOLATED COMMON-CERTIFICATE STATUS QUALIFICATION. No fetch, enrollment or product import.
import * as asn from 'asn1js';
import * as pki from 'pkijs';
const PIN='63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179';
const need=v=>{if(!v)throw new Error('status_qualification_rejected');};
const same=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
const bytes=(v,max)=>{need(v instanceof Uint8Array&&v.length>0&&v.length<=max);return v.slice();};
const digest=async v=>new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const hex=v=>[...v].map(x=>x.toString(16).padStart(2,'0')).join('');
function parse(v,max=65536){
 const r=asn.fromBER(v,{maxDepth:24,maxNodes:4096,maxContentLength:max,parseEmbedded:false});need(r.offset===v.length&&!r.result.error);
 const walk=n=>{need(!n.lenBlock.isIndefiniteForm);if(n.idBlock.isConstructed)n.valueBlock.value.forEach(walk);};walk(r.result);return r.result;
}
const certificate=v=>new pki.Certificate({schema:parse(v,8192)});
const valid=(c,now)=>{need(Number.isSafeInteger(now)&&now>=c.notBefore.value.getTime()&&now<c.notAfter.value.getTime());};
const marker=(c,oid)=>{const found=(c.extensions??[]).filter(e=>e.extnID===oid);need(found.length===1&&!found[0].critical&&same(found[0].extnValue.valueBlock.valueHexView,new Uint8Array([5,0])));};
async function context(certBytes,issuerBytes,rootBytes,pin,now){
 need(hex(await digest(rootBytes))===pin);
 const cert=certificate(certBytes),issuer=certificate(issuerBytes),root=certificate(rootBytes),engine=new pki.CryptoEngine({name:'status-qualification',crypto,subtle:crypto.subtle});
 for(const c of [cert,issuer,root])valid(c,now);
 need(root.subject.isEqual(root.issuer)&&await root.verify(root,engine));
 if(same(issuerBytes,rootBytes)){marker(cert,'1.2.840.113635.100.6.2.3');}
 else{marker(cert,'1.2.840.113635.100.12.15');marker(issuer,'1.2.840.113635.100.6.2.3');need(issuer.issuer.isEqual(root.subject)&&await issuer.verify(root,engine));}
 need(cert.issuer.isEqual(issuer.subject)&&await cert.verify(issuer,engine));
 return {cert,issuer,root,engine,certificateExpiry:Math.min(...[cert,issuer,root].map(c=>c.notAfter.value.getTime()))};
}
async function ocsp(response,certBytes,issuerBytes,rootBytes,pin,now){
 const ctx=await context(certBytes,issuerBytes,rootBytes,pin,now);
 const node=parse(response);need(node instanceof asn.Sequence&&node.valueBlock.value.length===2);
 const outer=new pki.OCSPResponse({schema:node});need(outer.responseStatus.valueBlock.valueDec===0&&outer.responseBytes?.responseType==='1.3.6.1.5.5.7.48.1.1');
 const basic=new pki.BasicOCSPResponse({schema:parse(outer.responseBytes.response.valueBlock.valueHexView)});
 need(basic.signatureAlgorithm.algorithmId==='1.2.840.10045.4.3.2'&&!basic.signatureAlgorithm.algorithmParams&&basic.signature.valueBlock.unusedBits===0);
 need(basic.certs?.length>0&&basic.certs.length<=3&&basic.tbsResponseData.responses.length===1);
 const single=basic.tbsResponseData.responses[0];
 need(single.certID.hashAlgorithm.algorithmId==='2.16.840.1.101.3.4.2.1');
 need(!(basic.tbsResponseData.responseExtensions??[]).some(e=>e.critical)&&!(single.singleExtensions??[]).some(e=>e.critical));
 // Patched maintained API validates responderID, chain AND CA delegation/EKU. No trustedResponders bypass.
 need(await basic.verify({trustedCerts:[ctx.root],issuerCerts:[ctx.issuer]},ctx.engine));
 const status=await basic.getCertificateStatus(ctx.cert,ctx.issuer,ctx.engine);need(status.isForCertificate&&status.status===0);
 const thisUpdate=single.thisUpdate.getTime(),nextUpdate=single.nextUpdate?.getTime(),producedAt=basic.tbsResponseData.producedAt.getTime();
 need([thisUpdate,nextUpdate,producedAt].every(Number.isSafeInteger)&&thisUpdate<=now&&producedAt<=now&&nextUpdate>thisUpdate&&now<nextUpdate&&now-thisUpdate<=86400000);
 for(const c of basic.certs)valid(c,now);
 const cacheUntil=Math.min(nextUpdate,thisUpdate+86400000,now+3600000,ctx.certificateExpiry,...basic.certs.map(c=>c.notAfter.value.getTime()));need(Date.now()<cacheUntil);
 return {scope:'COMMON_RECEIPT_OCSP_GOOD_ONLY_NO_ENROLLMENT',checkedAt:now,cacheUntil,thisUpdate,nextUpdate};
}
async function crl(response,certBytes,issuerBytes,rootBytes,pin,now){
 need(same(issuerBytes,rootBytes));const ctx=await context(certBytes,issuerBytes,rootBytes,pin,now);
 const list=new pki.CertificateRevocationList({schema:parse(response)});
 need(list.issuer.isEqual(ctx.root.subject)&&await list.verify({issuerCertificate:ctx.root},ctx.engine));
 const map=new Map();for(const e of list.crlExtensions?.extensions??[]){need(!map.has(e.extnID)&&['2.5.29.35','2.5.29.20'].includes(e.extnID)&&!e.critical);map.set(e.extnID,e);}
 const aki=map.get('2.5.29.35')?.parsedValue,ski=(ctx.root.extensions??[]).find(e=>e.extnID==='2.5.29.14')?.parsedValue;
 need(aki instanceof pki.AuthorityKeyIdentifier&&aki.keyIdentifier&&ski instanceof asn.OctetString&&same(aki.keyIdentifier.valueBlock.valueHexView,ski.valueBlock.valueHexView));
 // Closed measured CRL profile: no entry extensions, including critical unknown scope.
 for(const entry of list.revokedCertificates??[])need(!entry.crlEntryExtensions?.extensions?.length);
 need(!list.isCertificateRevoked(ctx.cert));
 const thisUpdate=list.thisUpdate.value.getTime(),nextUpdate=list.nextUpdate?.value.getTime();need(Number.isSafeInteger(thisUpdate)&&Number.isSafeInteger(nextUpdate)&&thisUpdate<=now&&nextUpdate>thisUpdate&&now<nextUpdate);
 const cacheUntil=Math.min(nextUpdate,now+3600000,ctx.certificateExpiry);need(Date.now()<cacheUntil);
 return {scope:'COMMON_RECEIPT_ISSUER_CRL_NOT_LISTED_ONLY_NO_ENROLLMENT',checkedAt:now,cacheUntil,thisUpdate,nextUpdate};
}
async function evaluate(kind,response,cert,issuer,root,pin,now){
 const args=[bytes(response,65536),bytes(cert,8192),bytes(issuer,8192),bytes(root,8192),pin,now];
 return kind==='ocsp'?ocsp(...args):kind==='crl'?crl(...args):null;
}
export async function qualifyCommonStatus(kind,response,cert,issuer,root){try{return await evaluate(kind,response,cert,issuer,root,PIN,Date.now());}catch{return null;}}
export async function qualifySyntheticStatus(f){try{need(f.scope==='synthetic-common-status-qualification-only');return await evaluate(f.kind,f.response,f.cert,f.issuer,f.root,f.pin,Date.now());}catch{return null;}}
async function binding(kind,cert,issuer,root){
 const tuple=[kind,hex(await digest(cert)),hex(await digest(issuer)),hex(await digest(root))];
 return hex(await digest(new TextEncoder().encode(JSON.stringify(tuple))));
}
export class CommonStatusCache {
 #entries=new Map();
 async put(kind,response,cert,issuer,root){
  response=bytes(response,65536);cert=bytes(cert,8192);issuer=bytes(issuer,8192);root=bytes(root,8192);
  const verified=await qualifyCommonStatus(kind,response,cert,issuer,root);if(!verified)return false;
  const id=await binding(kind,cert,issuer,root);if(Date.now()<verified.checkedAt||Date.now()>=verified.cacheUntil)return false;this.#entries.set(id,Object.freeze({...verified}));return true;
 }
 async get(kind,cert,issuer,root){
  const id=await binding(kind,bytes(cert,8192),bytes(issuer,8192),bytes(root,8192)),value=this.#entries.get(id);
  if(!value||Date.now()<value.checkedAt||Date.now()<value.thisUpdate||Date.now()>=value.cacheUntil){this.#entries.delete(id);return null;}
  return {...value}; // Never renew checkedAt/cacheUntil on read; map cannot be seeded with caller status:good.
 }
}
