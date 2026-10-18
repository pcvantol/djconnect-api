// Qualification-only candidate. Not imported by src/, not a complete verifier.
import * as asn1js from 'asn1js';
import * as pki from 'pkijs';

export const APPLE_ROOT_SHA256 = '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932';
const OID = {
  bc: '2.5.29.19', ku: '2.5.29.15', eku: '2.5.29.37', ski: '2.5.29.14', aki: '2.5.29.35',
  nonce: '1.2.840.113635.100.8.2', appEku: '1.2.840.113635.100.4.24',
};
function requireValue(value) { if (!value) throw new Error('qualification_rejected'); }
function bytes(value) { return new Uint8Array(value); }
function same(left, right) {
  const a = bytes(left), b = bytes(right);
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function certificate(encoded) {
  requireValue(encoded instanceof Uint8Array && encoded.length > 0 && encoded.length <= 8192);
  const decoded = asn1js.fromBER(encoded);
  requireValue(decoded.offset === encoded.length && !decoded.result.error);
  const result = new pki.Certificate({ schema: decoded.result });
  requireValue(same(result.toSchema().toBER(false), encoded));
  return result;
}
function extensions(cert, leaf) {
  const result = new Map();
  const allowed = new Set([OID.bc, OID.ku, OID.ski, OID.aki,
    ...(leaf ? [OID.eku, OID.nonce, '1.2.840.113635.100.8.5', '1.2.840.113635.100.8.6', '1.2.840.113635.100.8.7'] : [])]);
  for (const extension of cert.extensions ?? []) {
    requireValue(!result.has(extension.extnID) && allowed.has(extension.extnID));
    // Closed measured certificate profile: only BC and KU may be critical.
    requireValue(!extension.critical || [OID.bc, OID.ku].includes(extension.extnID));
    result.set(extension.extnID, extension);
  }
  return result;
}
function extension(map, oid, critical) {
  const value = map.get(oid);
  requireValue(value && Boolean(value.critical) === critical);
  return value;
}
function ski(map) {
  const value = extension(map, OID.ski, false).parsedValue;
  requireValue(value instanceof asn1js.OctetString && value.valueBlock.valueHexView.length > 0);
  return value.valueBlock.valueHexView;
}
function akiMatches(map, issuerSki, optional) {
  if (!map.has(OID.aki)) { requireValue(optional); return; }
  const value = extension(map, OID.aki, false).parsedValue;
  requireValue(value instanceof pki.AuthorityKeyIdentifier && value.keyIdentifier &&
    !value.authorityCertIssuer && !value.authorityCertSerialNumber &&
    same(value.keyIdentifier.valueBlock.valueHexView, issuerSki));
}
function shape(cert, map, leaf, intermediatesBelow) {
  const serial = cert.serialNumber.valueBlock.valueHexView;
  requireValue(cert.version === 2 && serial.length > 0 && serial.length <= 20 && !(serial[0] & 0x80) &&
    serial.some(value => value !== 0) && !(serial.length > 1 && serial[0] === 0 && serial[1] < 0x80));
  requireValue(cert.signatureValue.valueBlock.unusedBits === 0 && cert.subjectPublicKeyInfo.subjectPublicKey.valueBlock.unusedBits === 0);
  const basic = extension(map, OID.bc, true).parsedValue;
  const usage = extension(map, OID.ku, true).parsedValue;
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
    const eku = extension(map, OID.eku, false).parsedValue;
    requireValue(eku instanceof pki.ExtKeyUsage && eku.keyPurposes.length === 1 && eku.keyPurposes[0] === OID.appEku);
    extension(map, OID.nonce, false); // Value/challenge checked by the separate composed verifier.
  }
}

async function evaluate(leafBytes, intermediateBytes, rootBytes, rootPin, now) {
  requireValue(Number.isSafeInteger(now));
  requireValue([leafBytes, intermediateBytes, rootBytes].every(value => value instanceof Uint8Array && value.length > 0 && value.length <= 8192));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', rootBytes));
  requireValue([...hash].map(value => value.toString(16).padStart(2, '0')).join('') === rootPin);
  const leaf = certificate(leafBytes), intermediate = certificate(intermediateBytes), root = certificate(rootBytes);
  const leafExtensions = extensions(leaf, true), interExtensions = extensions(intermediate, false), rootExtensions = extensions(root, false);
  shape(leaf, leafExtensions, true, 0); shape(intermediate, interExtensions, false, 0); shape(root, rootExtensions, false, 1);
  akiMatches(rootExtensions, ski(rootExtensions), true); // Self-signed root AKI is optional under strict PKI.
  akiMatches(interExtensions, ski(rootExtensions), false);
  akiMatches(leafExtensions, ski(interExtensions), true); // The reviewed missing-leaf-AKI compatibility rule.
  requireValue(root.subject.isEqual(root.issuer) && intermediate.issuer.isEqual(root.subject) && leaf.issuer.isEqual(intermediate.subject));
  for (const cert of [leaf, intermediate, root]) {
    requireValue(now >= cert.notBefore.value.getTime() && now < cert.notAfter.value.getTime());
  }
  const engine = new pki.CryptoEngine({ name: 'qualification-webcrypto', crypto, subtle: crypto.subtle });
  const leafKey = await leaf.getPublicKey(undefined, engine); // Standard import validates the EC point.
  requireValue(leafKey.type === 'public' && leafKey.algorithm.name === 'ECDSA' && leafKey.algorithm.namedCurve === 'P-256');
  requireValue(await root.verify(root, engine));
  const validator = new pki.CertificateChainValidationEngine({ trustedCerts: [root], certs: [intermediate, leaf], checkDate: new Date(now) });
  // No supplied CRL/OCSP data means revocation is NOT qualified; no network fetch or claimed good status.
  const result = await validator.verify({}, engine);
  requireValue(result.result === true && result.certificatePath?.length === 3);
  for (const [index, expected] of [leafBytes, intermediateBytes, rootBytes].entries()) {
    requireValue(same(result.certificatePath[index].toSchema().toBER(false), expected));
  }
  return true;
}

// Fixed real anchor + server clock; no client-selectable trust or time in this wrapper.
export async function qualifyApplePath(leaf, intermediate, root) {
  try { return await evaluate(leaf, intermediate, root, APPLE_ROOT_SHA256, Date.now()); }
  catch { return false; }
}

// Deliberately TEST-ONLY: synthetic PKI anchors and controlled-time negative cases.
// Never import this qualification module as a production auth implementation.
export async function qualifySyntheticPath(fixture) {
  try {
    requireValue(fixture.scope === 'synthetic-qualification-only');
    return await evaluate(fixture.leaf, fixture.intermediate, fixture.root, fixture.rootPin, fixture.now);
  } catch { return false; }
}
