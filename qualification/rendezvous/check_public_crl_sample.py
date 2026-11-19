#!/usr/bin/env python3
"""Verify the committed public CRL sample; never fetch or establish device/signer status."""
import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID

def main():
 base=Path(__file__).resolve().parent
 raw=(base/'apple-receipt-root.cer').read_bytes()
 assert hashlib.sha256(raw).hexdigest()=='63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179'
 root=x509.load_der_x509_certificate(raw)
 crl=x509.load_der_x509_crl((base/'apple-root-g3-crl-sample.der').read_bytes())
 root.public_key().verify(crl.signature,crl.tbs_certlist_bytes,ec.ECDSA(crl.signature_hash_algorithm))
 assert crl.issuer==root.subject
 assert crl.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier==root.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
 now=datetime.now(timezone.utc)
 print(json.dumps({'scope':'PUBLIC_DATED_CRL_SAMPLE_ONLY_NOT_SIGNER_STATUS_OR_ADMISSION','signature_issuer_aki_verified':True,'valid_at_current_time':crl.last_update_utc<=now<crl.next_update_utc,'revoked_entries':len(crl)}))
if __name__=='__main__':main()
