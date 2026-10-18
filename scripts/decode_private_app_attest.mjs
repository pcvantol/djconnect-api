// Offline private-fixture qualification only. Not a Worker or public verifier.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';

async function main() {
  const [fixtureDirectory, dependencyDirectory, outputDirectory] = process.argv.slice(2);
  assert.ok(fixtureDirectory && dependencyDirectory && outputDirectory);
  const requireDependency = createRequire(join(resolve(dependencyDirectory), 'package.json'));
  const cbor = requireDependency('cbor');
  assert.equal(requireDependency('cbor/package.json').version, '10.0.11');
  const options = { preventDuplicateKeys: true, preferMap: true, max_depth: 8 };
  const checks = [];
  function closed(map, keys) {
    assert.ok(map instanceof Map);
    assert.equal(map.size, keys.length);
    for (const key of keys) assert.ok(map.has(key));
    return map;
  }
  function decode(bytes, maximum = 32768) {
    assert.ok(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= maximum);
    return cbor.decodeFirstSync(bytes, options); // Rejects trailing bytes.
  }
  function extensions(bytes, version) {
    const map = closed(decode(bytes, 1024), ['apple_bundle_version_01', 'apple_validation_category_01']);
    assert.equal(map.get('apple_bundle_version_01'), version);
    const category = map.get('apple_validation_category_01');
    assert.ok(Buffer.isBuffer(category) && category.equals(Buffer.from([3, 0, 0, 0])));
    return { version, development_category: 3 };
  }
  const b64 = bytes => bytes.toString('base64');
  const root = resolve(fixtureDirectory);
  const first = join(root, 'device-evidence');
  const second = join(root, 'reuse-evidence');
  const state = JSON.parse(await readFile(join(first, 'state.json'), 'utf8'));
  const output = { scope: 'PRIVATE_OFFLINE_QUALIFICATION_ONLY', slots: {}, decoder_checks: checks };
  for (const slot of ['active', 'replacement']) {
    const original = await readFile(join(first, `${slot}-attestation.cbor`));
    const reused = await readFile(join(second, `${slot}-attestation.cbor`));
    assert.ok(original.equals(reused));
    const attestation = closed(decode(original), ['fmt', 'attStmt', 'authData']);
    assert.equal(attestation.get('fmt'), 'apple-appattest');
    const statement = closed(attestation.get('attStmt'), ['x5c', 'receipt']);
    const certs = statement.get('x5c');
    assert.ok(Array.isArray(certs) && certs.length === 2 && certs.every(x => Buffer.isBuffer(x) && x.length < 8192));
    const receipt = statement.get('receipt');
    assert.ok(Buffer.isBuffer(receipt) && receipt.length > 0 && receipt.length < 16384);
    const auth = attestation.get('authData');
    assert.ok(Buffer.isBuffer(auth) && auth.length >= 87 && auth.length < 2048);
    // Measured iOS27 development fixture profile, not general WebAuthn flags.
    assert.equal(auth[32], 0xc0);
    assert.equal(auth.readUInt32BE(33), 0);
    assert.ok(auth.subarray(37, 53).equals(Buffer.from('appattestdevelop')));
    assert.equal(auth.readUInt16BE(53), 32);
    const credential = auth.subarray(55, 87);
    assert.equal(typeof state[slot], 'string');
    assert.ok(Buffer.from(state[slot], 'base64').equals(credential));
    const restoredState = JSON.parse(await readFile(join(second, 'state.json'), 'utf8'));
    assert.equal(restoredState[slot], state[slot]);
    const coseResult = cbor.decodeFirstSync(auth.subarray(87), { ...options, extendedResults: true });
    const cose = closed(coseResult.value, [1, 3, -1, -2, -3]);
    assert.equal(cose.get(1), 2); assert.equal(cose.get(3), -7); assert.equal(cose.get(-1), 1);
    for (const key of [-2, -3]) assert.ok(Buffer.isBuffer(cose.get(key)) && cose.get(key).length === 32);
    extensions(coseResult.unused, '40227');
    const assertions = [];
    for (let index = 1; index <= 4; index++) {
      const directory = index <= 2 ? first : second;
      const bytes = await readFile(join(directory, `${slot}-assert-${index}.cbor`));
      const proof = closed(decode(bytes, 4096), ['signature', 'authenticatorData']);
      const data = proof.get('authenticatorData');
      const signature = proof.get('signature');
      assert.ok(Buffer.isBuffer(data) && data.length >= 37 && data.length < 2048);
      assert.ok(Buffer.isBuffer(signature) && signature.length >= 8 && signature.length <= 80);
      assert.equal(data[32], 0xc0); assert.equal(data.readUInt32BE(33), index);
      extensions(data.subarray(37), index <= 2 ? '40227' : '40228');
      assertions.push({ auth: b64(data), signature: b64(signature),
        input: b64(await readFile(join(directory, `${slot}-assert-${index}-input.bin`))), counter: index });
    }
    output.slots[slot] = { certificates: certs.map(b64), receipt: b64(receipt), auth: b64(auth),
      input: b64(await readFile(join(first, `${slot}-attestation-input.bin`))),
      credential: b64(credential), cose_x: b64(cose.get(-2)), cose_y: b64(cose.get(-3)), assertions };
  }
  // Malformed parser controls contain no real device evidence.
  const cases = [
    ['trailing-object', Buffer.from([0xa0, 0xa0])],
    ['duplicate-text-map-key', Buffer.from([0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])],
    ['duplicate-integer-map-key', Buffer.from([0xa2, 0x01, 0x01, 0x01, 0x02])],
    ['truncated', Buffer.from([0xa1])], ['invalid-utf8', Buffer.from([0x61, 0xff])],
    ['invalid-indefinite-text', Buffer.from([0x7f, 0x61, 0xff, 0xff])],
    ['depth-limit', Buffer.from([...Array(12).fill(0x81), 0x01])],
    ['payload-limit', Buffer.alloc(32769)],
  ];
  for (const [name, bytes] of cases) {
    assert.throws(() => decode(bytes)); checks.push({ name, result: 'rejected' });
  }
  const wrongExtensionCases = [
    ['unknown-extension', new Map([['apple_bundle_version_01', '40227'], ['apple_validation_category_01', Buffer.from([3, 0, 0, 0])], ['extra', true]])],
    ['wrong-category-type', new Map([['apple_bundle_version_01', '40227'], ['apple_validation_category_01', 3]])],
    ['wrong-version', new Map([['apple_bundle_version_01', 'other'], ['apple_validation_category_01', Buffer.from([3, 0, 0, 0])]])],
    ['camelcase-substitution', new Map([['bundleVersion', '40227'], ['validationCategory', Buffer.from([3, 0, 0, 0])]])],
  ];
  for (const [name, value] of wrongExtensionCases) {
    const bytes = await cbor.encodeAsync(value);
    assert.throws(() => extensions(bytes, '40227')); checks.push({ name, result: 'rejected' });
  }
  assert.notEqual(output.slots.active.credential, output.slots.replacement.credential);
  const boundaryDirectory = join(root, 'input-evidence');
  const boundaryState = JSON.parse(await readFile(join(boundaryDirectory, 'state.json'), 'utf8'));
  assert.equal(boundaryState.active, state.active);
  output.input_boundary = {};
  for (const [name, filename, counter] of [
    ['accepted_raw_hash_31', 'unexpected-hash-31.cbor', 5],
    ['next_normal_assertion', 'active-assert-5.cbor', 6],
  ]) {
    const proof = closed(decode(await readFile(join(boundaryDirectory, filename)), 4096), ['signature', 'authenticatorData']);
    const auth = proof.get('authenticatorData'), signature = proof.get('signature');
    assert.ok(Buffer.isBuffer(auth) && auth.length >= 37 && auth.length < 2048);
    assert.ok(Buffer.isBuffer(signature) && signature.length <= 80);
    assert.equal(auth[32], 0xc0); assert.equal(auth.readUInt32BE(33), counter);
    extensions(auth.subarray(37), '40230');
    output.input_boundary[name] = { auth: b64(auth), signature: b64(signature), counter };
  }
  output.input_boundary.next_normal_assertion.input = b64(
    await readFile(join(boundaryDirectory, 'active-assert-5-input.bin')));
  output.expected_app_hash = createHash('sha256').update('ZEML4LPXH4.dev.djconnect.ios').digest('base64');
  await mkdir(resolve(outputDirectory), { recursive: true, mode: 0o700 });
  assert.equal((await stat(resolve(outputDirectory))).mode & 0o077, 0);
  await writeFile(join(resolve(outputDirectory), 'decoded-private.json'), JSON.stringify(output), { mode: 0o600, flag: 'wx' });
  console.log('Private fixture decoding complete; 2 attestations, 10 assertions including SDK boundary, 12 negative parser controls. No runtime approval.');
}
main().catch(() => { console.error('Private fixture decoding FAILED; raw errors suppressed.'); process.exitCode = 1; });
