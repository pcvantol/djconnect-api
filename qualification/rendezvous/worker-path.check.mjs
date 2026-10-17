// Optional isolated workerd qualification; deliberately outside normal *.spec/test globs.
import { test, expect, vi } from 'vitest';
import { qualifyApplePath, qualifySyntheticPath } from './worker-path-candidate.mjs';
import fixtures from 'djc-qa-fixtures';

const decode = value => Uint8Array.from(atob(value), x => x.charCodeAt(0));
for (const fixture of fixtures.synthetic) {
  test('synthetic signed path: ' + fixture.name, async () => {
    const value = { ...fixture, leaf: decode(fixture.leaf), intermediate: decode(fixture.intermediate), root: decode(fixture.root) };
    expect(await qualifySyntheticPath(value)).toBe(fixture.expected);
  });
}
for (const fixture of fixtures.genuine) {
  const leaf = decode(fixture.leaf), intermediate = decode(fixture.intermediate), root = decode(fixture.root);
  test('genuine reviewed path: ' + fixture.name, async () => {
    expect(await qualifyApplePath(leaf, intermediate, root)).toBe(true);
  });
  for (const part of ['leaf', 'intermediate']) {
    test('genuine damaged ' + part + ': ' + fixture.name, async () => {
      const changed = (part === 'leaf' ? leaf : intermediate).slice(); changed[changed.length - 1] ^= 1;
      expect(await qualifyApplePath(part === 'leaf' ? changed : leaf, part === 'intermediate' ? changed : intermediate, root)).toBe(false);
    });
  }
  test('genuine reversed chain: ' + fixture.name, async () => {
    expect(await qualifyApplePath(intermediate, leaf, root)).toBe(false);
  });
  test('genuine wrong intermediate: ' + fixture.name, async () => {
    expect(await qualifyApplePath(leaf, root, root)).toBe(false);
  });
  for (const [name, at] of [['not-yet-valid', fixture.notBefore - 1], ['expired', fixture.notAfter]]) {
    test('genuine time fault ' + name + ': ' + fixture.name, async () => {
      vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(at);
      try { expect(await qualifyApplePath(leaf, intermediate, root)).toBe(false); }
      finally { vi.useRealTimers(); }
    });
  }
}
if (fixtures.genuine.length) {
  test('no external fetch during genuine path qualification', async () => {
    const spy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('qualification_network_forbidden'));
    try {
      for (const value of fixtures.genuine) {
        expect(await qualifyApplePath(decode(value.leaf), decode(value.intermediate), decode(value.root))).toBe(true);
      }
      expect(spy).not.toHaveBeenCalled();
    } finally { spy.mockRestore(); }
  });
  test('parallel valid and invalid verification keeps trust isolated', async () => {
    const [a, b] = fixtures.genuine;
    const bad = decode(a.leaf); bad[bad.length - 1] ^= 1;
    const results = await Promise.all([
      qualifyApplePath(decode(a.leaf), decode(a.intermediate), decode(a.root)),
      qualifyApplePath(bad, decode(a.intermediate), decode(a.root)),
      qualifyApplePath(decode(b.leaf), decode(b.intermediate), decode(b.root)),
      qualifyApplePath(decode(b.leaf), decode(b.root), decode(b.root)),
    ]);
    expect(results.map(Boolean).join(',')).toBe('true,false,true,false');
  });
}
test('fixed Apple wrapper never trusts the synthetic test root', async () => {
  const value = fixtures.synthetic.find(value => value.name === 'valid');
  expect(await qualifyApplePath(decode(value.leaf), decode(value.intermediate), decode(value.root))).toBe(false);
});
