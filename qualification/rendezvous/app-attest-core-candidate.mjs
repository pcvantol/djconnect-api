// ISOLATED QUALIFICATION ONLY. Receipt/CMS, wire challenge lifecycle and DO state are NOT VERIFIED here.
import cbor from 'cbor';
import * as asn1js from 'asn1js';
import * as pki from 'pkijs';
import { qualifyApplePath } from './worker-path-candidate.mjs';
const APP = 'ZEML4LPXH4.dev.djconnect.ios';
const BUILDS = new Set(['40227', '40228', '40230']);
const assert = value => { if (!value) throw new Error('qualification_rejected'); };
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const hash = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
const concat = (a, b) => { const bytes = new Uint8Array(a.length + b.length); bytes.set(a); bytes.set(b, a.length); return bytes; };
const uint32 = (bytes, at) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(at, false);
function buffer(value, min, max) { assert(value instanceof Uint8Array && value.length >= min && value.length <= max); return value; }
function decode(bytes, max, extended = false) {
  buffer(bytes, 1, max);
  return cbor.decodeFirstSync(Buffer.from(bytes), { preventDuplicateKeys: true, preferMap: true, max_depth: 8, extendedResults: extended });
}
function closed(value, keys) {
  assert(value instanceof Map && value.size === keys.length && keys.every(key => value.has(key))); return value;
}
function der(bytes) {
  const value = asn1js.fromBER(bytes);
  assert(value.offset === bytes.length && !value.result.error && equal(new Uint8Array(value.result.toBER(false)), bytes));
  return value.result;
}
function properties(bytes) {
  const map = closed(decode(bytes, 1024), ['apple_bundle_version_01', 'apple_validation_category_01']);
  assert(BUILDS.has(map.get('apple_bundle_version_01')));
  assert(equal(buffer(map.get('apple_validation_category_01'), 4, 4), new Uint8Array([3, 0, 0, 0])));
}
async function prefix(auth) {
  assert(auth[32] === 0xc0); // Measured iOS development distribution; not a generic WebAuthn flag parser.
  assert(equal(auth.subarray(0, 32), await hash(new TextEncoder().encode(APP))));
}
function signedInput(bytes) { return buffer(bytes, 1, 2048); }
function keyId(text) {
  assert(typeof text === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(text));
  const bytes = Uint8Array.from(atob(text), char => char.charCodeAt(0));
  assert(bytes.length === 32 && btoa(String.fromCharCode(...bytes)) === text); return bytes;
}
export async function qualifyAttestationCore(encoded, savedClientData, canonicalKeyId, publicRoot) {
  try {
    signedInput(savedClientData);
    const object = closed(decode(encoded, 32768), ['fmt', 'attStmt', 'authData']);
    assert(object.get('fmt') === 'apple-appattest');
    const statement = closed(object.get('attStmt'), ['x5c', 'receipt']);
    const chain = statement.get('x5c');
    assert(Array.isArray(chain) && chain.length === 2);
    const [leaf, intermediate] = chain.map(value => buffer(value, 1, 8192));
    const receipt = buffer(statement.get('receipt'), 1, 16384);
    assert(await qualifyApplePath(leaf, intermediate, publicRoot));
    const auth = buffer(object.get('authData'), 88, 2048);
    await prefix(auth); assert(uint32(auth, 33) === 0);
    assert(equal(auth.subarray(37, 53), new TextEncoder().encode('appattestdevelop')));
    assert(new DataView(auth.buffer, auth.byteOffset, auth.byteLength).getUint16(53, false) === 32);
    const credential = keyId(canonicalKeyId);
    assert(equal(auth.subarray(55, 87), credential));
    const decoded = decode(auth.subarray(87), 1961, true);
    const cose = closed(decoded.value, [1, 3, -1, -2, -3]);
    assert(cose.get(1) === 2 && cose.get(3) === -7 && cose.get(-1) === 1);
    const point = concat(new Uint8Array([4]), concat(buffer(cose.get(-2), 32, 32), buffer(cose.get(-3), 32, 32)));
    properties(buffer(decoded.unused, 1, 1024));
    const certificate = new pki.Certificate({ schema: der(leaf) });
    assert(equal(point, certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView));
    assert(equal(await hash(point), credential));
    const extensions = certificate.extensions.filter(value => value.extnID === '1.2.840.113635.100.8.2');
    assert(extensions.length === 1 && !extensions[0].critical);
    const nonce = der(extensions[0].extnValue.valueBlock.valueHexView);
    assert(nonce instanceof asn1js.Sequence && nonce.valueBlock.value.length === 1);
    const tagged = nonce.valueBlock.value[0];
    assert(tagged instanceof asn1js.Constructed && tagged.idBlock.tagClass === 3 && tagged.idBlock.tagNumber === 1 && tagged.valueBlock.value.length === 1);
    const octets = tagged.valueBlock.value[0];
    assert(octets instanceof asn1js.OctetString && !octets.idBlock.isConstructed && octets.valueBlock.valueHexView.length === 32);
    const expectedNonce = await hash(concat(auth, await hash(savedClientData)));
    assert(equal(octets.valueBlock.valueHexView, expectedNonce));
    // Rebuild this exact nonce structure with fresh ASN.1 nodes: decoding may preserve BER length forms.
    const canonicalNonce = new asn1js.Sequence({ value: [new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 1 },
      value: [new asn1js.OctetString({ valueHex: expectedNonce })] })] });
    assert(equal(new Uint8Array(canonicalNonce.toBER(false)), extensions[0].extnValue.valueBlock.valueHexView));
    // Internal composition output only: already authenticated by this exact path/nonce check.
    const certificateExpiresAt = Math.min(...[certificate, ...[intermediate, publicRoot].map(value => new pki.Certificate({ schema: der(value) }))].map(value => value.notAfter.value.getTime()));
    return { scope: 'ATTESTATION_CORE_ONLY_RECEIPT_UNVERIFIED_NO_ENROLLMENT', point, receipt, attestedLeaf: leaf.slice(), certificateExpiresAt };
  } catch { return null; }
}
function assertionSignature(encoded) {
  buffer(encoded, 8, 72);
  assert(encoded[0] === 0x30 && encoded[1] === encoded.length - 2); // DER short length required below128.
  const sequence = der(encoded);
  assert(sequence instanceof asn1js.Sequence && sequence.valueBlock.value.length === 2);
  for (const integer of sequence.valueBlock.value) {
    assert(integer instanceof asn1js.Integer && !integer.idBlock.isConstructed &&
      integer.idBlock.blockLength === 1 && integer.lenBlock.blockLength === 1 && !integer.lenBlock.isIndefiniteForm);
    const bytes = integer.valueBlock.valueHexView;
    assert(bytes.length > 0 && bytes.length <= 33 && !(bytes[0] & 0x80) && bytes.some(v => v !== 0));
    assert(!(bytes.length > 1 && bytes[0] === 0 && bytes[1] < 0x80));
    assert(bytes.length < 33 || bytes[0] === 0);
  }
  // Standard PKIJS adapter; no handwritten DER/P1363 conversion.
  const raw = new Uint8Array(pki.createECDSASignatureFromCMS(sequence, 32));
  assert(raw.length === 64); return raw;
}
export async function qualifyAssertionCore(encoded, savedClientData, storedPoint, previousCounter) {
  try {
    signedInput(savedClientData); buffer(storedPoint, 65, 65);
    assert(storedPoint[0] === 4 && Number.isInteger(previousCounter) && previousCounter >= 0 && previousCounter <= 0xffffffff);
    const object = closed(decode(encoded, 4096), ['signature', 'authenticatorData']);
    const auth = buffer(object.get('authenticatorData'), 38, 2048);
    await prefix(auth); properties(auth.subarray(37));
    const counter = uint32(auth, 33); assert(counter > previousCounter);
    const key = await crypto.subtle.importKey('raw', storedPoint, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const nonce = await hash(concat(auth, await hash(savedClientData)));
    // Apple signatures cover nonce using ECDSA-with-SHA256, as proven by actual device fixtures.
    assert(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, assertionSignature(object.get('signature')), nonce));
    return { scope: 'ASSERTION_CRYPTO_ONLY_NO_ATOMIC_COUNTER_OR_WIRE_ADMISSION', counter };
  } catch { return null; }
}
