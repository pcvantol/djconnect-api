// Optional local qualification runner. No installation, deploy, or cloud API calls.
import { mkdir, readFile, writeFile, symlink, stat, realpath } from 'node:fs/promises';
import { dirname, resolve, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { createHash, X509Certificate } from 'node:crypto';
import { spawnSync } from 'node:child_process';

async function main() {
  const repository = resolve(fileURLToPath(new URL('../../', import.meta.url)));
  const [dependencyArgument, outputArgument, decodedArgument] = process.argv.slice(2);
  if (!dependencyArgument || !outputArgument) throw new Error('usage');
  const dependencies = await realpath(resolve(dependencyArgument));
  const output = join(await realpath(dirname(resolve(outputArgument))), resolve(outputArgument).split(sep).at(-1));
  for (const value of [dependencies, output]) {
    if (value === repository || value.startsWith(repository + sep)) throw new Error('isolated_directory_required');
  }
  for (const [name, expected] of [['pkijs', '3.4.1'], ['asn1js', '3.1.0']]) {
    const data = JSON.parse(await readFile(join(dependencies, 'node_modules', name, 'package.json'), 'utf8'));
    if (data.version !== expected) throw new Error('dependency_pin');
  }
  await mkdir(output, { mode: 0o700 }); // Never overwrite a previous evidence directory.
  if ((await stat(output)).mode & 0o077) throw new Error('private_directory_required');
  const put = (name, text) => writeFile(join(output, name), text, { mode: 0o600, flag: 'wx' });
  await symlink(join(repository, 'node_modules'), join(output, 'node_modules'), 'dir');
  const synthetic = JSON.parse(await readFile(new URL('./synthetic-pki-v1.json', import.meta.url), 'utf8')).cases;
  const root = new X509Certificate(await readFile(new URL('./apple-attestation-root.pem', import.meta.url)));
  const rootHash = createHash('sha256').update(root.raw).digest('hex');
  if (rootHash !== '1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932') throw new Error('root_pin');
  const genuine = [];
  if (decodedArgument) {
    const decodedPath = await realpath(resolve(decodedArgument));
    if (decodedPath.startsWith(repository + sep) || (await stat(dirname(decodedPath))).mode & 0o077) throw new Error('private_fixture_location');
    const decoded = JSON.parse(await readFile(decodedPath, 'utf8'));
    if (Object.keys(decoded.slots).sort().join(',') !== 'active,replacement') throw new Error('fixture_slots');
    for (const name of ['active', 'replacement']) {
      const data = decoded.slots[name], cert = new X509Certificate(Buffer.from(data.certificates[0], 'base64'));
      genuine.push({ name, leaf: data.certificates[0], intermediate: data.certificates[1], root: root.raw.toString('base64'),
        notBefore: cert.validFromDate.getTime(), notAfter: cert.validToDate.getTime() });
    }
  }
  await put('fixtures.mjs', 'export default ' + JSON.stringify({ synthetic, genuine }) + ';\n');
  const sourceHashes = {};
  for (const name of ['worker-path-candidate.mjs', 'worker-path.check.mjs']) {
    const source = await readFile(new URL('./' + name, import.meta.url));
    sourceHashes[name] = createHash('sha256').update(source).digest('hex');
    await put(name, source);
  }
  await put('worker.mjs', "export default {fetch(){return new Response('qualification only',{status:503})}};\n");
  await put('wrangler.jsonc', JSON.stringify({ name: 'djc-private-path-qualification', main: 'worker.mjs', workers_dev: false,
    compatibility_date: '2026-06-20', compatibility_flags: ['nodejs_compat'], send_metrics: false, observability: { enabled: false } }));
  await put('vitest.config.mts', `import {defineConfig} from 'vitest/config';
import {cloudflareTest} from '@cloudflare/vitest-pool-workers';
export default defineConfig({resolve:{alias:${JSON.stringify({
    pkijs: join(dependencies, 'node_modules/pkijs/build/index.es.js'),
    asn1js: join(dependencies, 'node_modules/asn1js/build/index.es.js'),
    'djc-qa-fixtures': join(output, 'fixtures.mjs'),
  })}},plugins:[cloudflareTest({wrangler:{configPath:'./wrangler.jsonc'}})],test:{include:['worker-path.check.mjs'],testTimeout:20000}});
`);
  const requireRepository = createRequire(join(repository, 'package.json'));
  const vitest = join(dirname(requireRepository.resolve('vitest/package.json')), 'vitest.mjs');
  const child = spawnSync(process.execPath, [vitest, 'run', '--config', 'vitest.config.mts', '--reporter=json', '--outputFile=results-private.json'],
    { cwd: output, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, WRANGLER_LOG_PATH: join(output, 'wrangler.log'), CLOUDFLARE_SEND_METRICS: 'false' } });
  await put('process-private.log', (child.stdout ?? '') + '\n' + (child.stderr ?? ''));
  if (child.status !== 0) throw new Error('workerd_qualification_failed');
  const result = JSON.parse(await readFile(join(output, 'results-private.json'), 'utf8'));
  if (!result.success || result.numFailedTests || result.numPendingTests) throw new Error('workerd_results');
  async function packageMetadata(resolver, name, entry) {
    let directory = dirname(entry ?? resolver.resolve(name));
    while (true) {
      try {
        const path = join(directory, 'package.json');
        const data = JSON.parse(await readFile(path, 'utf8'));
        if (data.name === name) return { path, version: data.version };
      } catch { /* Continue to the owning package directory. */ }
      const parent = dirname(directory);
      if (parent === directory) throw new Error('package_metadata');
      directory = parent;
    }
  }
  const poolMetadata = await packageMetadata(requireRepository, '@cloudflare/vitest-pool-workers',
    fileURLToPath(import.meta.resolve('@cloudflare/vitest-pool-workers')));
  const poolRequire = createRequire(poolMetadata.path);
  const miniflareMetadata = await packageMetadata(poolRequire, 'miniflare');
  const miniflarePackage = miniflareMetadata.path;
  const miniflareRequire = createRequire(miniflarePackage);
  const workerdMetadata = await packageMetadata(miniflareRequire, 'workerd');
  const summary = {
    scope: 'LOCAL_WORKERD_CERTIFICATE_PATH_CANDIDATE_NOT_COMPLETE_VERIFIER',
    tests_passed: result.numPassedTests, synthetic_cases: synthetic.length, genuine_paths: genuine.length,
    cases: result.testResults.flatMap(file => file.assertionResults.map(test => ({ name: test.fullName, status: test.status }))),
    node: process.version, pkijs: '3.4.1', asn1js: '3.1.0', source_sha256: sourceHashes,
    pool: poolMetadata.version, miniflare: miniflareMetadata.version, workerd: workerdMetadata.version,
    compatibility_date: '2026-06-20', compatibility_flags: ['nodejs_compat'],
    not_run: [...(genuine.length ? [] : ['genuine private Apple paths']), 'full composed App Attest verifier/CMS', 'revocation availability', 'enrollment/DO/recovery/races', 'production or HA/TV chain'],
  };
  await put('summary-sanitized.json', JSON.stringify(summary, null, 2) + '\n');
  console.log('PASS: ' + summary.tests_passed + ' local workerd cases; sanitized summary saved. No runtime GO.');
}
main().catch(() => { console.error('Workerd qualification failed; raw diagnostics stay private.'); process.exitCode = 1; });
