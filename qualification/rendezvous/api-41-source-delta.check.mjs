import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,mkdirSync,chmodSync,symlinkSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';

// Isolate the JS checks by mocking only the Python precheck. This is a test
// fixture, not an authorization or an evidence-producing workflow.
test('JS source transition rejects each tampered pinned file', {timeout: 90000}, () => {
  const source = fileURLToPath(new URL('../..', import.meta.url));
  const lab = mkdtempSync(join(tmpdir(), 'djc-api-delta-js-'));
  const checkout = join(lab, 'source'), bin = join(lab, 'bin');
  const run = (cmd,args,opts={}) => spawnSync(cmd,args,{encoding:'utf8',...opts});
  const git = (args) => {const x=run('git',args,{cwd:checkout});assert.equal(x.status,0,x.stderr);};
  try {
    let x=run('git',['clone','--quiet','--shared',source,checkout]);assert.equal(x.status,0,x.stderr);
    symlinkSync(join(source,'node_modules'),join(checkout,'node_modules'));
    writeFileSync(join(checkout,'.git/info/exclude'),'\n/node_modules\n',{flag:'a'});
    const baseline=run('python3',['scripts/validate_rendezvous_deployment_plan.py'],{cwd:checkout});assert.equal(baseline.status,0,baseline.stderr);
    assert.equal(JSON.parse(baseline.stdout).activation_allowed,false);
    mkdirSync(bin);const preparation=join(bin,'preparation.json');writeFileSync(preparation,baseline.stdout);
    writeFileSync(join(bin,'python3'),'#!/bin/sh\ncat "$DJC_TEST_PREPARATION"\n');chmodSync(join(bin,'python3'),0o755);
    const env={...process.env,PATH:`${bin}:${process.env.PATH}`,DJC_TEST_PREPARATION:preparation};
    const check=()=>run(process.execPath,['--input-type=module','-e','import {sourceSnapshot} from "./qualification/rendezvous/local-native-runtime.mjs"; await sourceSnapshot();'],{cwd:checkout,env});
    x=check();assert.equal(x.status,0,x.stderr);
    const deltaPath='docs/rendezvous/api-4-1-org-policy-source-delta-v1.json';
    const delta=JSON.parse(readFileSync(join(checkout,deltaPath),'utf8'));
    const manifestPath='docs/rendezvous/api-4-1-manifest-refresh-delta-v1.json';
    const manifests=JSON.parse(readFileSync(join(checkout,manifestPath),'utf8'));
    for(const file of [...Object.keys(delta.workflow_changes),...Object.keys(delta.version_source_changes),...Object.keys(manifests.manifest_changes),deltaPath,manifestPath]){
      const path=join(checkout,file),original=readFileSync(path);
      git(['update-index','--assume-unchanged','--',file]);
      try {
        writeFileSync(path,Buffer.concat([original,Buffer.from('\n')]));
        x=check();assert.notEqual(x.status,0,`${file} unexpectedly accepted`);
      } finally {
        writeFileSync(path,original);git(['update-index','--no-assume-unchanged','--',file]);
      }
    }
    x=check();assert.equal(x.status,0,x.stderr);
  } finally { rmSync(lab,{recursive:true,force:true}); }
});
