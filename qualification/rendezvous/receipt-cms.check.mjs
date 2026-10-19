// Optional receipt evidence qualification. No public admission or product imports.
import {test,expect,vi} from 'vitest';
import * as asn from 'asn1js';
import * as pki from 'pkijs';
import fixtures from 'djc-receipt-fixtures';
import {qualifyReceiptEvidence,qualifyFreshReceiptEvidence,qualifySyntheticReceipt} from './receipt-cms-candidate.mjs';
const decode=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0));
const root=decode(fixtures.root);
for(const f of fixtures.synthetic){
  test('signed synthetic CMS: '+f.name,async()=>{
    const value={...f,...Object.fromEntries(['encoded','attestedCert','clientData','anchor'].map(k=>[k,decode(f[k])]))};
    const result=await qualifySyntheticReceipt(value);
    expect(Boolean(result)).toBe(f.valid);
    if(f.valid){expect(result.fresh).toBe(f.fresh);expect(result.scope).toBe('CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT');}
  });
}
test('fixed real-root wrapper cannot trust synthetic fixture root',async()=>{
  const f=fixtures.synthetic[0];expect(await qualifyReceiptEvidence(decode(f.encoded),decode(f.attestedCert),decode(f.clientData),decode(f.anchor))).toBeNull();
});
function cms(value){const outer=new pki.ContentInfo({schema:asn.fromBER(value,{parseEmbedded:false}).result});return new pki.SignedData({schema:outer.content});}
function encode(sd){return new Uint8Array(new pki.ContentInfo({contentType:pki.ContentInfo.SIGNED_DATA,content:sd.toSchema(true)}).toSchema().toBER(false));}
function createdAt(receipt){
  const sd=cms(receipt),parsed=asn.fromBER(sd.encapContentInfo.eContent.getValue(),{parseEmbedded:false}).result;
  const field=parsed.valueBlock.value.find(v=>v.valueBlock.value[0].valueBlock.valueDec===12);
  return Date.parse(new TextDecoder().decode(field.valueBlock.value[2].valueBlock.valueHexView));
}
for(const f of fixtures.genuine){
  const receipt=decode(f.receipt),leaf=decode(f.attestedCert),input=decode(f.clientData);
  test('genuine Apple BER signature/path/fields: '+f.name,async()=>{
    const result=await qualifyReceiptEvidence(receipt,leaf,input,root);
    expect(result?.scope).toBe('CMS_SIGNATURE_PATH_FIELDS_ONLY_REVOCATION_UNCHECKED_NO_ENROLLMENT');expect(result.fresh).toBe(false);
  });
  test('genuine archived receipt denied for current fresh use: '+f.name,async()=>{
    expect(await qualifyFreshReceiptEvidence(receipt,leaf,input,root)).toBeNull();
  });
  for(const [name,offset,fresh] of [['created-plus-1s',1000,true],['exact-5min',300000,true],['after-5min',300001,false],['future-creation',-1,false]]){
    test('genuine controlled-time receipt '+name+': '+f.name,async()=>{
      vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(createdAt(receipt)+offset);
      try{expect(Boolean(await qualifyFreshReceiptEvidence(receipt,leaf,input,root))).toBe(fresh);}finally{vi.useRealTimers();}
    });
  }
  for(const [name,change] of [
    ['saved-challenge',v=>{v.input[0]^=1;}],['attested-key',v=>{v.leaf[10]^=1;}],['wrong-root',v=>{v.root[v.root.length-1]^=1;}],
    ['signature',v=>{const sd=cms(v.receipt);sd.signerInfos[0].signature.valueBlock.valueHexView[10]^=1;v.receipt=encode(sd);}],
    ['duplicate-signer',v=>{const sd=cms(v.receipt);sd.signerInfos.push(sd.signerInfos[0]);v.receipt=encode(sd);}],
    ['unsigned-attrs',v=>{const sd=cms(v.receipt);sd.signerInfos[0].unsignedAttrs=new pki.SignedAndUnsignedAttributes({type:1,attributes:[new pki.Attribute({type:'1.2.3.4',values:[new asn.Null()]})]});v.receipt=encode(sd);}],
    ['wrong-signer-id',v=>{const sd=cms(v.receipt);sd.signerInfos[0].sid.serialNumber=new asn.Integer({value:1});v.receipt=encode(sd);}],
    ['extra-cert',v=>{const sd=cms(v.receipt);sd.certificates.push(sd.certificates[0]);v.receipt=encode(sd);}],
    ['trailing-object',v=>{v.receipt=Uint8Array.from([...v.receipt,5,0]);}],['truncated',v=>{v.receipt=v.receipt.subarray(0,v.receipt.length-1);}],
    ['oversize',v=>{v.receipt=new Uint8Array(16385);}],
  ]){
    test('genuine CMS negative '+name+': '+f.name,async()=>{
      const v={receipt:receipt.slice(),leaf:leaf.slice(),input:input.slice(),root:root.slice()};change(v);
      expect(await qualifyReceiptEvidence(v.receipt,v.leaf,v.input,v.root)).toBeNull();
    });
  }
  test('BER-to-definite encoding preserves valid signed evidence: '+f.name,async()=>{
    expect(await qualifyReceiptEvidence(encode(cms(receipt)),leaf,input,root)).not.toBeNull();
  });
  test('CMS certificate SET reordering is supported: '+f.name,async()=>{
    const sd=cms(receipt);sd.certificates.reverse();expect(await qualifyReceiptEvidence(encode(sd),leaf,input,root)).not.toBeNull();
  });
}
if(fixtures.genuine.length){
  test('no network fetch during genuine receipt checks',async()=>{
    const spy=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('network_forbidden'));
    try{for(const f of fixtures.genuine)expect(await qualifyReceiptEvidence(decode(f.receipt),decode(f.attestedCert),decode(f.clientData),root)).not.toBeNull();expect(spy).not.toHaveBeenCalled();}finally{spy.mockRestore();}
  });
}
