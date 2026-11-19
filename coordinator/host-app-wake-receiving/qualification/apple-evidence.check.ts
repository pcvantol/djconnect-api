import {describe,it,expect,vi} from 'vitest';
import * as asn from 'asn1js';import * as pki from 'pkijs';import cbor from 'cbor';
import rootPEM from '../../../qualification/rendezvous/apple-attestation-root.pem?raw';
import {verifyAppleAttestationEvidence} from '../native-apple-evidence.mjs';
import {RequestWindow} from '../request-window';
// Actual pinned Apple root is public. Children and their private signing keys
// below are entirely SOFTWARE FORGERIES and MUST NOT become native authority.
const der=(n:{toSchema():{toBER(indefinite?:boolean):ArrayBuffer}})=>new Uint8Array(n.toSchema().toBER(false));
async function forgedChain(){
 const rootBytes=Uint8Array.from(atob(rootPEM.replace(/-----[^-]+-----|\s/g,'')),c=>c.charCodeAt(0));const root=new pki.Certificate({schema:asn.fromBER(rootBytes).result});
 const intermediatePair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-384'},true,['sign','verify']) as CryptoKeyPair,leafPair=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']) as CryptoKeyPair;
 const engine=Object.assign(new pki.CryptoEngine({name:'software-forgery-only',crypto,subtle:crypto.subtle}),{timingSafeEqual:(a:BufferSource,b:BufferSource)=>crypto.subtle.timingSafeEqual(a,b)});
 const rootSki=(root.extensions!.find(e=>e.extnID==='2.5.29.14')!.parsedValue as asn.OctetString).valueBlock.valueHexView,interSki=new Uint8Array(20).fill(0x42),leafSki=new Uint8Array(20).fill(0x43);
 const make=async(leaf:boolean)=>{
  const cert=new pki.Certificate();cert.version=2;cert.serialNumber=new asn.Integer({value:leaf?44:43});cert.notBefore.value=new Date(Date.now()-60000);cert.notAfter.value=new Date(Date.now()+3600000);
  cert.subject=new pki.RelativeDistinguishedNames({typesAndValues:[new pki.AttributeTypeAndValue({type:'2.5.4.3',value:new asn.Utf8String({value:leaf?'SYNTHETIC DEVICE NOT APPLE':'SYNTHETIC ISSUER NOT APPLE'})})]});
  cert.issuer=leaf?new pki.RelativeDistinguishedNames({schema:intermediate.subject.toSchema()}):new pki.RelativeDistinguishedNames({schema:root.subject.toSchema()});
  const basic=new pki.BasicConstraints({cA:!leaf,...(!leaf?{pathLenConstraint:0}:{})}),usage=new asn.BitString({unusedBits:leaf?7:1,valueHex:new Uint8Array([leaf?0x80:6]).buffer});
  cert.extensions=[new pki.Extension({extnID:'2.5.29.19',critical:true,extnValue:basic.toSchema().toBER(false)}),new pki.Extension({extnID:'2.5.29.15',critical:true,extnValue:usage.toBER(false)}),new pki.Extension({extnID:'2.5.29.14',extnValue:new asn.OctetString({valueHex:(leaf?leafSki:interSki).buffer}).toBER(false)}),new pki.Extension({extnID:'2.5.29.35',extnValue:new pki.AuthorityKeyIdentifier({keyIdentifier:new asn.OctetString({valueHex:Uint8Array.from(leaf?interSki:rootSki).buffer})}).toSchema().toBER(false)})];
  if(leaf)cert.extensions.push(new pki.Extension({extnID:'2.5.29.37',extnValue:new pki.ExtKeyUsage({keyPurposes:['1.2.840.113635.100.4.24']}).toSchema().toBER(false)}),new pki.Extension({extnID:'1.2.840.113635.100.8.2',extnValue:new asn.Sequence({value:[new asn.Constructed({idBlock:{tagClass:3,tagNumber:1},value:[new asn.OctetString({valueHex:new Uint8Array(32).buffer})]})]}).toBER(false)}));
  await cert.subjectPublicKeyInfo.importKey(leaf?leafPair.publicKey:intermediatePair.publicKey,engine);await cert.sign(intermediatePair.privateKey,leaf?'SHA-256':'SHA-384',engine);return cert;
 };
 const intermediate=await make(false),leaf=await make(true);
 return {encoded:new Uint8Array(cbor.encode(new Map<string,unknown>([['fmt','apple-appattest'],['attStmt',new Map<string,unknown>([['x5c',[Buffer.from(der(leaf)),Buffer.from(der(intermediate))]],['receipt',Buffer.from('NOT A RECEIPT')]])],['authData',Buffer.alloc(200)]]))),keyId:btoa('A'.repeat(32))};
}
const policy={profile:'host_wake_apple_properties_attestation_v2',app_identifier:'ABCDEFGHIJ.example.fixture.host',app_attest_environment:'development',bundle_version:'1.0',launch_validation_category_b64:btoa(String.fromCharCode(3,0,0,0))};
describe('real pinned Apple root crypto with software-forged children, NO genuine native positive proof',()=>{
 it('rejects a forged chain even with copied Apple issuer DN/AKI and valid software child signatures, before any status fetch',async()=>{
  const forged=await forgedChain(),window=new RequestWindow(()=>Date.now(),new AbortController().signal);let calls=0;try{expect(await verifyAppleAttestationEvidence(forged.encoded,new TextEncoder().encode('SYNTHETIC R31 DATA'),forged.keyId,policy,window,async()=>{calls++;throw Error('NO FETCH');})).toBeNull();expect(calls).toBe(0);}finally{window.close();}
 });
 it('preserves the identical unexpected fixed-root signature-verification cause instead of treating it as bad client proof',async()=>{
  const forged=await forgedChain(),window=new RequestWindow(()=>Date.now(),new AbortController().signal),failure=new Error('synthetic-fixed-root-verifier-unavailable'),spy=vi.spyOn(crypto.subtle,'verify').mockRejectedValueOnce(failure);
  try{await expect(verifyAppleAttestationEvidence(forged.encoded,new TextEncoder().encode('SYNTHETIC DATA'),forged.keyId,policy,window,fetch)).rejects.toBe(failure);}finally{spy.mockRestore();window.close();}
 });
});
