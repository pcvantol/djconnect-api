// Causal real-Git controls in owned disposable repositories only. No API refs.
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,readFile,writeFile,symlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const repo=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const source=await readFile(join(repo,'scripts/build_rendezvous_qa.mjs'),'utf8');
const needle="spawnSync('git',['--no-replace-objects',...args],";
assert.equal(source.split(needle).length,2);
const control=source.replace(needle,"spawnSync('git',args,");
const output=await mkdtemp(join(tmpdir(),'djc-qa-replace-proof-'));await chmod(output,0o700);
const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith('GIT_')));
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const observations=[];
for(const [label,code]of [['old-no-global-guard',control],['fixed-global-guard',source]]){
 const root=join(output,label);await mkdir(join(root,'scripts'),{recursive:true});
 const git=(...args)=>{const r=spawnSync('git',['--no-replace-objects',...args],{cwd:root,env,encoding:'utf8'});assert.equal(r.status,0,r.stderr);return r.stdout.trim();};
 git('init','--quiet');git('config','user.name','QA Disposable Fixture');git('config','user.email','qa@example.invalid');git('config','commit.gpgsign','false');git('config','core.useReplaceRefs','true');
 await writeFile(join(root,'.gitignore'),'node_modules\n');await symlink(join(repo,'node_modules'),join(root,'node_modules'),'dir');
 await writeFile(join(root,'scripts/build_rendezvous_qa.mjs'),code);await writeFile(join(root,'probe.txt'),'approved-A\n');
 git('add','.');git('commit','--quiet','-m','approved fixture A');const approved=git('rev-parse','HEAD');
 await writeFile(join(root,'probe.txt'),'unapproved-B\n');git('add','probe.txt');git('commit','--quiet','-m','different fixture B');const substituted=git('rev-parse','HEAD');
 git('replace',approved,substituted);git('update-ref','HEAD',approved);
 assert.equal(git('show',approved+':probe.txt'),'approved-A');assert.equal(await readFile(join(root,'probe.txt'),'utf8'),'unapproved-B\n');
 const module=await import(pathToFileURL(join(root,'scripts/build_rendezvous_qa.mjs')).href);
 const wrongPin=hash('unapproved-B\n');
 if(label==='old-no-global-guard'){
  // Same real helper, with ONLY the global guard removed: wrong clean stamp and
  // wrong replacement blob are actually accepted under the approved SHA.
  assert.equal(await module.fixedGitIdentity(),approved);
  assert.doesNotThrow(()=>module.verifyCommittedInput(approved,'probe.txt',wrongPin));
  observations.push({control:label,wrong_clean_stamp_reproduced:true,wrong_replacement_blob_reproduced:true});
 }else{
  await assert.rejects(module.fixedGitIdentity(),/clean committed worktree/);
  assert.throws(()=>module.verifyCommittedInput(approved,'probe.txt',wrongPin),/differs from exact committed source/);
  observations.push({control:label,wrong_clean_stamp_refused:true,wrong_replacement_blob_refused:true});
 }
}
const receipt={scope:'DISPOSABLE_REAL_GIT_REPLACEMENT_CAUSAL_PROOF_NO_API_REF_WRITES',result:'PASS',control_delta:'ONLY_GLOBAL_NO_REPLACE_OBJECTS_FLAG',source_helper_sha256:hash(source),control_helper_sha256:hash(control),observations};
await writeFile(join(output,'observations.json'),JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify({output,...receipt}));
