#!/usr/bin/env python3
"""Public fake receipt CMS fixtures only; synthetic private keys stay in memory."""
import sys,json,base64,hashlib
from datetime import datetime,timedelta,timezone
from pathlib import Path
from asn1crypto import core,cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,pkcs7
from cryptography.x509.oid import NameOID,ObjectIdentifier
class Attribute(core.Sequence): _fields=[('type',core.Integer),('version',core.Integer),('value',core.OctetString)]
class Attributes(core.SetOf): _child_spec=Attribute

def main():
 now=datetime(2026,10,17,12,tzinfo=timezone.utc)
 rk,ik,lk=ec.generate_private_key(ec.SECP384R1()),ec.generate_private_key(ec.SECP256R1()),ec.generate_private_key(ec.SECP256R1())
 names=[x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic receipt '+role)]) for role in ['Root','Intermediate','Signer']]
 def certificate(index,variant):
  key=[rk,ik,lk][index]; signer=[rk,rk,ik][index]; ca=index<2
  before,after=now-timedelta(days=1),now+timedelta(days=1)
  role=['root','inter','leaf'][index]
  if variant==role+'-expired':after=now-timedelta(seconds=1)
  if variant==role+'-future':before=now+timedelta(seconds=1)
  b=x509.CertificateBuilder().subject_name(names[index]).issuer_name(names[0 if index<2 else 1]).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
  if variant==role+'-wrong-ca':ca=not ca
  b=b.add_extension(x509.BasicConstraints(ca,None),critical=True)
  b=b.add_extension(x509.KeyUsage(index==2,False,False,False,False,index<2,index<2,False,False),critical=True)
  b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
  if variant!=role+'-missing-aki':b=b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),critical=False)
  if index>0 and variant!=role+'-missing-purpose':
   b=b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.840.113635.100.12.15' if index==2 else '1.2.840.113635.100.6.2.3'),b'\x05\x00'),critical=False)
  if variant==role+'-unknown-critical':b=b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\x00'),critical=True)
  return b.sign(signer,hashes.SHA256() if index==2 else hashes.SHA384())
 variants=['valid','wrong-app','wrong-attested-cert','wrong-client-hash','wrong-type','wrong-environment','duplicate-field','unknown-field','missing-field','wrong-field-version','wrong-field-value-type','invalid-date','expires-before-created','stale','future-receipt','fresh-at-300s','stale-at-300s-plus-1ms','expired-receipt',
  'leaf-missing-aki','inter-missing-aki','leaf-missing-purpose','inter-missing-purpose','leaf-wrong-ca','inter-wrong-ca','root-wrong-ca','leaf-unknown-critical','inter-unknown-critical','leaf-expired','inter-expired','root-expired','leaf-future','inter-future','root-future','signed-attrs','wrong-digest','duplicate-signer','extra-certificate','wrong-signer-id','tampered-signature','tampered-payload','trailing-object','truncated','wrong-root-pin']
 cases=[];b64=lambda v:base64.b64encode(v).decode()
 for variant in variants:
  root,inter,leaf=[certificate(i,variant) for i in range(3)]
  client=b'saved synthetic enrollment clientData';attested=b'synthetic prior attested certificate binding'
  created=now-timedelta(seconds=1)
  if variant=='stale':created=now-timedelta(seconds=301)
  if variant=='future-receipt':created=now+timedelta(milliseconds=1)
  if variant=='fresh-at-300s':created=now-timedelta(seconds=300)
  if variant=='stale-at-300s-plus-1ms':created=now-timedelta(seconds=300,milliseconds=1)
  expiry=now+timedelta(days=1)
  if variant=='expires-before-created':expiry=created-timedelta(seconds=1)
  if variant=='expired-receipt':created=now-timedelta(seconds=2);expiry=now
  stamp=lambda d:d.isoformat(timespec='milliseconds').replace('+00:00','Z').encode()
  fields={2:b'ZEML4LPXH4.dev.djconnect.ios',3:attested,4:hashlib.sha256(client).digest(),5:b'synthetic opaque token',6:b'ATTEST',7:b'sandbox',12:stamp(created),21:stamp(expiry)}
  for match,field,value in [('wrong-app',2,b'other.invalid.app'),('wrong-attested-cert',3,b'other key'),('wrong-client-hash',4,bytes(32)),('wrong-type',6,b'RECEIPT'),('wrong-environment',7,b'production'),('invalid-date',12,b'2026-02-30T12:00:00.000Z')]:
   if variant==match:fields[field]=value
  attrs=[Attribute({'type':k,'version':2 if variant=='wrong-field-version' and k==2 else 1,'value':v}) for k,v in fields.items()]
  if variant=='duplicate-field':attrs.append(attrs[0])
  if variant=='unknown-field':attrs.append(Attribute({'type':99,'version':1,'value':b'unknown'}))
  if variant=='missing-field':attrs=attrs[1:]
  payload=Attributes(attrs).dump()
  if variant=='wrong-field-value-type':
   nodes=[core.Any.load(item.dump()) for item in attrs]
   nodes[0]=core.Any.load(core.SequenceOf(spec=core.Any,value=[core.Integer(2),core.Integer(1),core.Integer(1)]).dump())
   payload=core.SetOf(spec=core.Any,value=[core.Any.load(n.dump()) for n in nodes]).dump()
  builder=pkcs7.PKCS7SignatureBuilder().set_data(payload).add_signer(leaf,lk,hashes.SHA384() if variant=='wrong-digest' else hashes.SHA256()).add_certificate(inter).add_certificate(root)
  options=[pkcs7.PKCS7Options.Binary]
  if variant!='signed-attrs':options.append(pkcs7.PKCS7Options.NoAttributes)
  encoded=builder.sign(Encoding.DER,options)
  if variant in ['duplicate-signer','extra-certificate','wrong-signer-id','tampered-signature','tampered-payload']:
   parsed=cms.ContentInfo.load(encoded);sd=parsed['content']
   if variant=='duplicate-signer':sd['signer_infos'].append(sd['signer_infos'][0])
   if variant=='extra-certificate':sd['certificates'].append(sd['certificates'][0])
   if variant=='wrong-signer-id':sd['signer_infos'][0]['sid'].chosen['serial_number']=1
   if variant=='tampered-signature':
    v=sd['signer_infos'][0]['signature'].native;sd['signer_infos'][0]['signature']=v[:-1]+bytes([v[-1]^1])
   if variant=='tampered-payload':sd['encap_content_info']['content']=payload[:-1]+bytes([payload[-1]^1])
   encoded=parsed.dump(force=True)
  if variant=='trailing-object':encoded+=b'\x05\x00'
  if variant=='truncated':encoded=encoded[:-1]
  rootder=root.public_bytes(Encoding.DER)
  cases.append({'name':variant,'scope':'synthetic-receipt-qualification-only','encoded':b64(encoded),'attestedCert':b64(attested),'clientData':b64(client),'anchor':b64(rootder),'pin':'0'*64 if variant=='wrong-root-pin' else hashlib.sha256(rootder).hexdigest(),'now':int(now.timestamp()*1000),'valid':variant in ['valid','stale','future-receipt','fresh-at-300s','stale-at-300s-plus-1ms','expired-receipt'],'fresh':variant in ['valid','fresh-at-300s']})
 Path(sys.argv[1]).write_text(json.dumps({'scope':'PUBLIC_FAKE_CMS_ONLY_NO_DEVICE_OR_PRIVATE_KEYS','cases':cases},indent=2)+'\n')
 print('Generated',len(cases),'public synthetic CMS cases; private keys never exported')
if __name__=='__main__':main()
