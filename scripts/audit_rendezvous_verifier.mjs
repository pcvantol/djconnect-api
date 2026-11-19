// Offline investigation of an unapproved reference, never a production verifier.
// Usage: node scripts/audit_rendezvous_verifier.mjs /absolute/path/to/exact-source
// That directory must contain the pinned verifyAssertion.js and its dependencies.
import assert from 'node:assert/strict';
import { createHash, createSign, generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const directory = process.argv[2];
assert.ok(directory, 'Supply the isolated exact-source directory; no automatic download');
const sourcePath = resolve(directory, 'verifyAssertion.js');
const source = await readFile(sourcePath);
const sourceHash = createHash('sha256').update(source).digest('hex');
assert.equal(sourceHash, '919f9678106318e787eb61fca1c37d2f0b2bca9cfe081e4110caaf996bd9e01b',
  'Reference source differs from the reviewed exact bytes');
const { default: verifyAssertion } = await import(pathToFileURL(sourcePath));
const requireReference = createRequire(sourcePath);
const cbor = requireReference('cbor');
assert.equal(requireReference('cbor/package.json').version, '10.0.11');
assert.equal(requireReference('nofilter/package.json').version, '3.1.0');
const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
// Ephemeral ordinary software keys exercise the reference's verification path.
// They are NOT Apple-attested keys and are never serialized or retained.
const payload = Buffer.from('synthetic-audit-client-data-not-a-real-request');
const teamIdentifier = 'AUDITONLY0';
const bundleIdentifier = 'invalid.example.audit';
const appHash = createHash('sha256').update(`${teamIdentifier}.${bundleIdentifier}`).digest();
async function assertion(counter, { tail = Buffer.alloc(0), duplicate = false, trailing = false } = {}) {
  const authenticatorData = Buffer.alloc(37);
  appHash.copy(authenticatorData);
  authenticatorData[32] = tail.length ? 0x80 : 0;
  authenticatorData.writeUInt32BE(counter, 33);
  const data = Buffer.concat([authenticatorData, tail]);
  const clientHash = createHash('sha256').update(payload).digest();
  const nonce = createHash('sha256').update(Buffer.concat([data, clientHash])).digest();
  const signer = createSign('SHA256');
  signer.update(nonce);
  const signature = signer.sign(privateKey);
  const encoded = duplicate
    ? Buffer.concat([
      Buffer.from([0xa3]), await cbor.encodeAsync('signature'), await cbor.encodeAsync(signature),
      await cbor.encodeAsync('authenticatorData'), await cbor.encodeAsync(Buffer.from('discarded')),
      await cbor.encodeAsync('authenticatorData'), await cbor.encodeAsync(data),
    ])
    : await cbor.encodeAsync({ signature, authenticatorData: data });
  return trailing ? Buffer.concat([encoded, await cbor.encodeAsync({ ignored: true })]) : encoded;
}
const defaults = { payload, publicKey, bundleIdentifier, teamIdentifier, signCount: 0 };
const results = [];
async function check(name, bytes, overrides, expected) {
  let actual = 'accepted';
  try { verifyAssertion({ ...defaults, ...overrides, assertion: await bytes }); }
  catch { actual = 'rejected'; }
  assert.equal(actual, expected, `${name}: reference behavior changed; reassess evidence`);
  results.push({ name, observed: actual });
}
await check('positive-synthetic-signature-counter1', assertion(1), {}, 'accepted');
await check('zero-counter-known-state', assertion(0), {}, 'rejected');
await check('equal-counter', assertion(1), { signCount: 1 }, 'rejected');
await check('lower-counter', assertion(1), { signCount: 2 }, 'rejected');
await check('omitted-counter-state-zero-accepted', assertion(0), { signCount: undefined }, 'accepted');
await check('nan-counter-state-zero-accepted', assertion(0), { signCount: Number.NaN }, 'accepted');
await check('second-cbor-object-ignored', assertion(1, { trailing: true }), {}, 'accepted');
await check('duplicate-map-key-accepted', assertion(1, { duplicate: true }), {}, 'accepted');
await check('unparsed-extension-tail-accepted', assertion(1, { tail: Buffer.from([0xff]) }), {}, 'accepted');
await check('unsigned-counter-high-bit-rejected', assertion(0x80000000), { signCount: 0x7fffffff }, 'rejected');
await check('unsigned-counter-maximum-rejected', assertion(0xffffffff), { signCount: 0xfffffffe }, 'rejected');
await check('changed-client-data', assertion(1), { payload: Buffer.from('changed') }, 'rejected');
await check('wrong-app-identity', assertion(1), { bundleIdentifier: 'invalid.example.other' }, 'rejected');
const changedSignature = cbor.decodeAllSync(await assertion(1))[0];
changedSignature.signature[changedSignature.signature.length - 1] ^= 1;
await check('changed-signature', await cbor.encodeAsync(changedSignature), {}, 'rejected');
const changedCounter = cbor.decodeAllSync(await assertion(1))[0];
changedCounter.authenticatorData.writeUInt32BE(2, 33);
await check('changed-signed-counter', await cbor.encodeAsync(changedCounter), {}, 'rejected');
console.log(JSON.stringify({
  evidence: 'UNAPPROVED_REFERENCE_BEHAVIOR_ONLY',
  reference_commit: 'f16c4bb71b737466872bc8b8a7dfd215364eaa83',
  source_sha256: sourceHash,
  node: process.version,
  cbor: requireReference('cbor/package.json').version,
  nofilter: requireReference('nofilter/package.json').version,
  cases: results.length,
  results,
  not_run: ['Apple attestation', 'actual App Attest assertion', 'full certificate path validation',
    'native interoperability', 'workerd/DO runtime', 'browser', 'HA', 'production'],
}, null, 2));
