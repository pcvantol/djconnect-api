// ISOLATED RECEIPT EVIDENCE ONLY. NO REVOCATION STATUS, ENROLLMENT OR PRODUCT IMPORT.
import * as asn from 'asn1js';
import * as pki from 'pkijs';
const ROOT = '63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179';
const APP = new TextEncoder().encode('ZEML4LPXH4.dev.djconnect.ios');
const OID = { bc:'2.5.29.19', ku:'2.5.29.15', ski:'2.5.29.14', aki:'2.5.29.35',
  leaf:'1.2.840.113635.100.12.15', inter:'1.2.840.113635.100.6.2.3',
  sha256:'2.16.840.1.101.3.4.2.1', ec256:'1.2.840.10045.4.3.2', ec384:'1.2.840.10045.4.3.3' };
const need = v => { if(!v) throw new Error('qualification_rejected'); };
const same = (a,b) => a.length===b.length && a.every((x,i)=>x===b[i]);
const raw = n => new Uint8Array(n.toSchema().toBER(false));
const hash = async v => new Uint8Array(await crypto.subtle.digest('SHA-256',v));
const bounded = (v,min,max) => { need(v instanceof Uint8Array && v.length>=min && v.length<=max); return v; };
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
async function evaluate(encoded,attestedCert,clientData,anchor,pin,now){
  bounded(attestedCert,1,8192);bounded(clientData,1,2048);bounded(anchor,1,8192);need(Number.isSafeInteger(now));
  need([...await hash(anchor)].map(v=>v.toString(16).padStart(2,'0')).join('')===pin);
  const outer=parse(encoded,16384,true),[contentType,wrapped]=seq(outer,2);
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
  const sd=new pki.SignedData({schema:sdNode});
  need(sd.version===1&&sd.signerInfos.length===1&&sd.certificates?.length===3&&!sd.crls&&!sd.ocsps);
  digest(sd.digestAlgorithms[0]);const si=sd.signerInfos[0];need(si.version===1&&si.sid instanceof pki.IssuerAndSerialNumber&&!si.signedAttrs&&!si.unsignedAttrs);
  digest(si.digestAlgorithm);algorithm(si.signatureAlgorithm,OID.ec256);signature(si.signature.valueBlock.valueHexView);
  need(sd.certificates.every(c=>c instanceof pki.Certificate));
  const root=new pki.Certificate({schema:parse(anchor,8192)});
  const roots=sd.certificates.filter(c=>same(raw(c),anchor));need(roots.length===1);
  const signers=sd.certificates.filter(c=>c.issuer.isEqual(si.sid.issuer)&&c.serialNumber.isEqual(si.sid.serialNumber));need(signers.length===1);
  const leaf=signers[0],others=sd.certificates.filter(c=>c!==leaf&&c!==roots[0]);need(leaf!==roots[0]&&others.length===1);const inter=others[0];
  certShape(root,'root',now);certShape(inter,'inter',now);certShape(leaf,'leaf',now);
  const ri=ext(root,'root'),ii=ext(inter,'inter'),li=ext(leaf,'leaf');aki(ri,ri,true);aki(ii,ri);aki(li,ii); // No missing leaf AKI exception for receipts.
  need(root.subject.isEqual(root.issuer)&&inter.issuer.isEqual(root.subject)&&leaf.issuer.isEqual(inter.subject));
  const engine=new pki.CryptoEngine({name:'receipt-qualification-only',crypto,subtle:crypto.subtle});
  need(await root.verify(root,engine)&&await inter.verify(root,engine)&&await leaf.verify(inter,engine));
  const path=await new pki.CertificateChainValidationEngine({trustedCerts:[root],certs:[inter,leaf],checkDate:new Date(now)}).verify({passedWhenNotRevValues:true},engine);
  // Explicit diagnostic bypass of absent revocation data, NEVER public admission.
  need(path.result===true&&path.certificatePath?.length===3);
  for(const [i,c] of [leaf,inter,root].entries())need(same(raw(path.certificatePath[i]),raw(c)));
  const verified=await sd.verify({signer:0,checkChain:false,extendedMode:true},engine);
  need(verified.signatureVerified===true&&verified.signerCertificate&&same(raw(verified.signerCertificate),raw(leaf)));
  const fields=payloadFields(body);
  need(same(fields.get(2),APP)&&same(fields.get(3),attestedCert)&&same(fields.get(4),await hash(clientData)));
  need(same(fields.get(6),new TextEncoder().encode('ATTEST'))&&same(fields.get(7),new TextEncoder().encode('sandbox')));
  bounded(fields.get(5),1,1024);const created=instant(fields.get(12)),expires=instant(fields.get(21));need(expires>created);
  // Internal authenticated common-cert tuple, never the device leaf from receipt field3.
  return {scope:'CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT',created,expires,fresh:now>=created&&now-created<=300000&&now<expires,
    signer:raw(leaf).slice(),issuer:raw(inter).slice(),root:raw(root).slice(),certificateExpiresAt:Math.min(...[leaf,inter,root].map(c=>c.notAfter.value.getTime()))};
}
export async function qualifyReceiptEvidence(encoded,attestedCert,clientData,anchor){
  try{return await evaluate(encoded,attestedCert,clientData,anchor,ROOT,Date.now());}catch{return null;}
}
export async function qualifyFreshReceiptEvidence(encoded,attestedCert,clientData,anchor){
  const result=await qualifyReceiptEvidence(encoded,attestedCert,clientData,anchor);return result?.fresh?result:null;
}
// Fake root/clock only for synthetic tests; no scope string establishes trust.
export async function qualifySyntheticReceipt(f){
  try{need(f.scope==='synthetic-receipt-qualification-only');return await evaluate(f.encoded,f.attestedCert,f.clientData,f.anchor,f.pin,f.now);}catch{return null;}
}
