#!/usr/bin/env python3
"""Public signed fake OCSP controls; no private device data or exported keys."""
import json,sys,base64,hashlib
from pathlib import Path
from datetime import datetime,timedelta,timezone
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ObjectIdentifier,ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from asn1crypto import ocsp as ao,core

def main():
 now=datetime(2026,10,17,12,tzinfo=timezone.utc)
 rk,ik,lk,ok=[ec.generate_private_key(c) for c in [ec.SECP384R1(),ec.SECP256R1(),ec.SECP256R1(),ec.SECP256R1()]]
 names=[x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic status '+n)]) for n in ['Root','Issuer','Receipt','Responder','Other']]
 def cert(index,key,issuer,signer,variant):
  ca=index<2;before,after=now-timedelta(days=2),now+timedelta(days=2)
  if index==3 and variant=='expired-responder':after=now-timedelta(seconds=1)
  if index==2 and variant=='expired-target':after=now-timedelta(seconds=1)
  b=x509.CertificateBuilder().subject_name(names[index]).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(before).not_valid_after(after)
  b=b.add_extension(x509.BasicConstraints(ca,None),critical=True).add_extension(x509.KeyUsage(not ca,False,False,False,False,ca,ca,False,False),critical=True)
  b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),critical=False)
  if index in [1,2]:b=b.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.840.113635.100.6.2.3' if index==1 else '1.2.840.113635.100.12.15'),b'\x05\x00'),critical=False)
  if index==3 and variant!='missing-responder-eku':b=b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),critical=False)
  return b.sign(signer,hashes.SHA384() if index<2 else hashes.SHA256())
 variants=['valid-delegation','issuer-signs-directly','revoked','unknown','wrong-target','wrong-certid-hash','missing-next-update','future-this-update','stale-this-update','next-update-equality','future-produced-at','missing-responder-eku','wrong-ca-delegation','expired-responder','expired-target','critical-response-extension','duplicate-single-response','missing-responder-certs','wrong-responder-id','tampered-signature','trailing-object','truncated','unsuccessful-response']
 cases=[];b64=lambda v:base64.b64encode(v).decode()
 for variant in variants:
  root=cert(0,rk,names[0],rk,variant);issuer=cert(1,ik,names[0],rk,variant);leaf=cert(2,lk,names[1],ik,variant)
  responder=cert(3,ok,names[0] if variant=='wrong-ca-delegation' else names[1],rk if variant=='wrong-ca-delegation' else ik,variant)
  this,next=now-timedelta(seconds=1),now+timedelta(hours=12)
  if variant=='future-this-update':this=now+timedelta(seconds=1)
  if variant=='stale-this-update':this=now-timedelta(hours=24,seconds=1)
  if variant=='next-update-equality':next=now
  if variant=='missing-next-update':next=None
  status=ocsp.OCSPCertStatus.REVOKED if variant=='revoked' else ocsp.OCSPCertStatus.UNKNOWN if variant=='unknown' else ocsp.OCSPCertStatus.GOOD
  target=cert(4,lk,names[1],ik,variant) if variant=='wrong-target' else leaf
  chosen,private=(issuer,ik) if variant=='issuer-signs-directly' else (responder,ok)
  builder=ocsp.OCSPResponseBuilder().add_response(target,issuer,hashes.SHA1() if variant=='wrong-certid-hash' else hashes.SHA256(),status,this,next,now-timedelta(minutes=1) if status==ocsp.OCSPCertStatus.REVOKED else None,x509.ReasonFlags.key_compromise if status==ocsp.OCSPCertStatus.REVOKED else None).responder_id(ocsp.OCSPResponderEncoding.HASH,chosen).certificates([chosen,issuer] if chosen!=issuer else [issuer])
  if variant=='critical-response-extension':builder=builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\x00'),critical=True)
  outer=ao.OCSPResponse.load(builder.sign(private,hashes.SHA256()).public_bytes(Encoding.DER));basic=outer['response_bytes']['response'].parsed
  basic['tbs_response_data']['produced_at']=now+timedelta(seconds=1) if variant=='future-produced-at' else now
  if variant=='duplicate-single-response':basic['tbs_response_data']['responses'].append(basic['tbs_response_data']['responses'][0])
  if variant=='wrong-responder-id':basic['tbs_response_data']['responder_id']={'by_key':bytes(20)}
  basic['signature']=private.sign(basic['tbs_response_data'].dump(force=True),ec.ECDSA(hashes.SHA256()))
  if variant=='missing-responder-certs':basic['certs']=None
  if variant=='tampered-signature':sig=basic['signature'].native;basic['signature']=sig[:-1]+bytes([sig[-1]^1])
  outer['response_bytes']['response']=core.ParsableOctetString(parsed=basic);encoded=outer.dump(force=True)
  if variant=='trailing-object':encoded+=b'\x05\x00'
  if variant=='truncated':encoded=encoded[:-1]
  if variant=='unsuccessful-response':encoded=ocsp.OCSPResponseBuilder.build_unsuccessful(ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(Encoding.DER)
  rootder=root.public_bytes(Encoding.DER)
  cases.append({'name':variant,'scope':'synthetic-common-status-qualification-only','kind':'ocsp','response':b64(encoded),'cert':b64(leaf.public_bytes(Encoding.DER)),'issuer':b64(issuer.public_bytes(Encoding.DER)),'root':b64(rootder),'pin':hashlib.sha256(rootder).hexdigest(),'now':int(now.timestamp()*1000),'valid':variant in ['valid-delegation','issuer-signs-directly']})
 for variant in ['crl-valid','crl-revoked','crl-critical-entry','crl-noncritical-entry','crl-unknown-extension','crl-wrong-aki','crl-future','crl-next-update-equality','crl-tampered-signature']:
  root=cert(0,rk,names[0],rk,variant);issuer=cert(1,ik,names[0],rk,variant)
  builder=x509.CertificateRevocationListBuilder().issuer_name(names[0]).last_update(now+timedelta(seconds=1) if variant=='crl-future' else now-timedelta(seconds=1)).next_update(now if variant=='crl-next-update-equality' else now+timedelta(days=30))
  builder=builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ik.public_key() if variant=='crl-wrong-aki' else rk.public_key()),critical=False).add_extension(x509.CRLNumber(1),critical=False)
  if variant=='crl-unknown-extension':builder=builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\x00'),critical=False)
  if variant in ['crl-revoked','crl-critical-entry','crl-noncritical-entry']:
   entry=x509.RevokedCertificateBuilder().serial_number(issuer.serial_number if variant=='crl-revoked' else issuer.serial_number+1).revocation_date(now-timedelta(seconds=1))
   if variant!='crl-revoked':entry=entry.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\x00'),critical=variant=='crl-critical-entry')
   builder=builder.add_revoked_certificate(entry.build())
  encoded=builder.sign(rk,hashes.SHA256()).public_bytes(Encoding.DER)
  if variant=='crl-tampered-signature':encoded=encoded[:-1]+bytes([encoded[-1]^1])
  rootder=root.public_bytes(Encoding.DER)
  cases.append({'name':variant,'scope':'synthetic-common-status-qualification-only','kind':'crl','response':b64(encoded),'cert':b64(issuer.public_bytes(Encoding.DER)),'issuer':b64(rootder),'root':b64(rootder),'pin':hashlib.sha256(rootder).hexdigest(),'now':int(now.timestamp()*1000),'valid':variant=='crl-valid'})
 Path(sys.argv[1]).write_text(json.dumps({'scope':'PUBLIC_FAKE_OCSP_ONLY_NO_DEVICE_OR_EXPORTED_KEYS','cases':cases},indent=2)+'\n');print('Generated',len(cases),'signed synthetic OCSP/CRL controls')
if __name__=='__main__':main()
