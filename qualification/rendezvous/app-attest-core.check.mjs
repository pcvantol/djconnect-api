// Optional isolated workerd qualification; never collected by ordinary test globs.
import { test, expect, vi } from 'vitest';
import cbor from 'cbor';
import * as pki from 'pkijs';
import fixtures from 'djc-core-fixtures';
import { qualifyAttestationCore, qualifyAssertionCore } from './app-attest-core-candidate.mjs';
const bytes = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
const encoded = value => new Uint8Array(cbor.encode(value));
const decoded = value => cbor.decodeFirstSync(Buffer.from(value), { preferMap: true });
const utf8 = value => new TextEncoder().encode(value);
const hash = async value => new Uint8Array(await crypto.subtle.digest('SHA-256', value));
const join = (a, b) => { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; };
const properties = () => new Map([['apple_bundle_version_01', '40230'], ['apple_validation_category_01', Buffer.from([3, 0, 0, 0])]]);
async function signed(counter, change = () => {}, client = utf8('saved synthetic challenge'), layer = 'apple') {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const point = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
  let auth = new Uint8Array(37); auth.set(await hash(utf8('ZEML4LPXH4.dev.djconnect.ios'))); auth[32] = 0xc0;
  new DataView(auth.buffer).setUint32(33, counter, false);
  const ext = properties(); const state = { auth, ext }; change(state);
  auth = join(state.auth, encoded(state.ext));
  const nonce = await hash(join(auth, await hash(client)));
  const signature = new Uint8Array(pki.createCMSECDSASignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, layer === 'apple' ? nonce : join(auth, await hash(client)))));
  return { proof: encoded(new Map([['signature', Buffer.from(signature)], ['authenticatorData', Buffer.from(auth)]])), point, client };
}
for (const counter of [1, 0x80000000, 0xffffffff]) {
  test('signed synthetic unsigned counter ' + counter, async () => {
    const f = await signed(counter); expect((await qualifyAssertionCore(f.proof, f.client, f.point, counter - 1))?.counter).toBe(counter);
  });
}
for (const [name, change] of [
  ['wrong-app', s => { s.auth[0] ^= 1; }], ['wrong-flags', s => { s.auth[32] = 0x40; }],
  ['unsupported-build', s => { s.ext.set('apple_bundle_version_01', 'other'); }],
  ['category-number', s => { s.ext.set('apple_validation_category_01', 3); }],
  ['category-wrong-value', s => { s.ext.set('apple_validation_category_01', Buffer.from([4, 0, 0, 0])); }],
  ['extra-extension', s => { s.ext.set('extra', true); }],
  ['camelcase-alias', s => { s.ext.delete('apple_bundle_version_01'); s.ext.set('bundleVersion', '40230'); }],
]) {
  test('correctly signed unsupported policy: ' + name, async () => {
    const f = await signed(1, change); expect(await qualifyAssertionCore(f.proof, f.client, f.point, 0)).toBeNull();
  });
}
for (const [name, previous] of [['replay', 1], ['older', 2], ['exhausted', 0xffffffff], ['negative', -1], ['fractional', 0.5], ['overflow', 0x100000000]]) {
  test('counter predicate rejects ' + name, async () => {
    const f = await signed(1); expect(await qualifyAssertionCore(f.proof, f.client, f.point, previous)).toBeNull();
  });
}
for (const [name, change] of [
  ['trailing', f => { f.proof = join(f.proof, new Uint8Array([0xa0])); }],
  ['wrong-clientData', f => { f.client = utf8('different saved challenge'); }],
  ['invalid-point', f => { f.point.fill(0, 1); }],
  ['empty-clientData', f => { f.client = new Uint8Array(); }],
  ['oversized-clientData', f => { f.client = new Uint8Array(2049); }],
  ['changed-signature', f => { const m = decoded(f.proof); m.get('signature')[10] ^= 1; f.proof = encoded(m); }],
  ['nonminimal-signature-sequence-length', f => { const m = decoded(f.proof); const s = m.get('signature'); m.set('signature', Buffer.from([0x30,0x81,s[1],...s.subarray(2)])); f.proof = encoded(m); }],
  ['trailing-signature-der', f => { const m = decoded(f.proof); m.set('signature', Buffer.from(join(m.get('signature'), new Uint8Array([0])))); f.proof = encoded(m); }],
  ['zero-signature-integers', f => { const m = decoded(f.proof); m.set('signature', Buffer.from([0x30,6,2,1,0,2,1,0])); f.proof = encoded(m); }],
  ['extra-proof-field', f => { const m = decoded(f.proof); m.set('extra', true); f.proof = encoded(m); }],
  ['string-signature', f => { const m = decoded(f.proof); m.set('signature', 'invalid'); f.proof = encoded(m); }],
]) {
  test('synthetic assertion rejects ' + name, async () => {
    const f = await signed(1); change(f); expect(await qualifyAssertionCore(f.proof, f.client, f.point, 0)).toBeNull();
  });
}
test('nonminimal DER rejected below payload ceiling with valid canonical control', async () => {
  let f, signature;
  for (let attempt = 0; attempt < 32; attempt++) {
    f = await signed(1); signature = decoded(f.proof).get('signature');
    if (signature.length <= 71) break;
  }
  expect(signature.length).toBeLessThanOrEqual(71);
  expect((await qualifyAssertionCore(f.proof, f.client, f.point, 0))?.counter).toBe(1);
  const m = decoded(f.proof); m.set('signature', Buffer.from([0x30,0x81,signature[1],...signature.subarray(2)]));
  expect(m.get('signature').length).toBeLessThanOrEqual(72);
  expect(await qualifyAssertionCore(encoded(m), f.client, f.point, 0)).toBeNull();
});
test('single-hash signature cannot substitute Apple nonce signature', async () => {
  const f = await signed(1, () => {}, utf8('saved synthetic challenge'), 'single-hash');
  expect(await qualifyAssertionCore(f.proof, f.client, f.point, 0)).toBeNull();
});
for (const [name, raw] of [
  ['duplicate-text', [0xa2,0x61,0x61,1,0x61,0x61,2]], ['duplicate-integer', [0xa2,1,1,1,2]],
  ['duplicate-nonminimal-integer', [0xa2,1,1,0x18,1,2]],
  ['truncated', [0xa1]], ['invalid-utf8', [0x61,0xff]], ['trailing-object', [0xa0,0xa0]],
  ['deep', [...Array(12).fill(0x81),1]],
]) {
  test('decoder itself rejects ' + name, () => {
    expect(() => cbor.decodeFirstSync(Buffer.from(raw), { preferMap: true, preventDuplicateKeys: true, max_depth: 8 })).toThrow();
  });
}
for (const [name, raw] of [
  ['duplicate-text', [0xa2,0x61,0x61,1,0x61,0x61,2]], ['duplicate-integer', [0xa2,1,1,1,2]],
  ['truncated', [0xa1]], ['invalid-utf8', [0x61,0xff]], ['tagged-map', [0xc0,0xa0]],
  ['trailing-object', [0xa0,0xa0]], ['deep', [...Array(12).fill(0x81),1]], ['overlong-payload', Array(32769).fill(0)],
]) {
  test('strict malformed CBOR: ' + name, async () => {
    const b = new Uint8Array(raw); expect(await qualifyAttestationCore(b, utf8('saved'), 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', bytes(fixtures.root))).toBeNull();
  });
}
for (const value of fixtures.genuine) {
  const attest = bytes(value.attestation), input = bytes(value.input), root = bytes(fixtures.root);
  test('genuine core binding (receipt still UNVERIFIED): ' + value.name, async () => {
    const result = await qualifyAttestationCore(attest, input, value.credential, root);
    expect(result?.scope).toBe('ATTESTATION_CORE_ONLY_RECEIPT_UNVERIFIED_NO_ENROLLMENT');
    expect(Buffer.from(result.point).toString('base64')).toBe(value.point);
  });
  for (const [name, mutate] of [
    ['challenge', f => { f.client[0] ^= 1; }], ['key-id', f => { f.id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='; }],
    ['noncanonical-key-id', f => { f.id = f.id.replace(/=$/, ''); }],
    ['nonce-authData', f => { const m=decoded(f.att); m.get('authData')[87] ^= 1; f.att=encoded(m); }],
    ['extra-attestation-field', f => { const m=decoded(f.att); m.set('extra', true); f.att=encoded(m); }],
    ['wrong-format', f => { const m=decoded(f.att); m.set('fmt','packed'); f.att=encoded(m); }],
    ['reversed-chain', f => { const m=decoded(f.att); m.get('attStmt').get('x5c').reverse(); f.att=encoded(m); }],
    ['missing-receipt', f => { const m=decoded(f.att); m.get('attStmt').delete('receipt'); f.att=encoded(m); }],
    ['empty-receipt', f => { const m=decoded(f.att); m.get('attStmt').set('receipt', Buffer.alloc(0)); f.att=encoded(m); }],
  ]) {
    test('genuine attestation rejects ' + name + ': ' + value.name, async () => {
      const f = { att: attest.slice(), client: input.slice(), id: value.credential }; mutate(f);
      expect(await qualifyAttestationCore(f.att, f.client, f.id, root)).toBeNull();
    });
  }
  for (const proof of value.assertions) {
    test('genuine assertion ' + value.name + ':' + proof.counter, async () => {
      const r = await qualifyAssertionCore(bytes(proof.proof), bytes(proof.input), bytes(value.point), proof.counter-1);
      expect(r?.counter).toBe(proof.counter);
    });
    test('genuine assertion replay denied ' + value.name + ':' + proof.counter, async () => {
      expect(await qualifyAssertionCore(bytes(proof.proof), bytes(proof.input), bytes(value.point), proof.counter)).toBeNull();
    });
    test('genuine assertion saved challenge mismatch ' + value.name + ':' + proof.counter, async () => {
      const changed = bytes(proof.input); changed[0] ^= 1;
      expect(await qualifyAssertionCore(bytes(proof.proof), changed, bytes(value.point), proof.counter-1)).toBeNull();
    });
  }
}
if (fixtures.boundary) {
  test('actual SDK raw31 signature is invalid for server SHA256 clientData', async () => {
    expect(await qualifyAssertionCore(bytes(fixtures.boundary.proof), utf8('saved input'), bytes(fixtures.genuine[0].point), 4)).toBeNull();
  });
  test('no outbound fetch during genuine core checks', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network_forbidden'));
    try {
      for (const f of fixtures.genuine) expect(await qualifyAttestationCore(bytes(f.attestation), bytes(f.input), f.credential, bytes(fixtures.root))).not.toBeNull();
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); }
  });
}
