/** Tampered artifacts and self-authored proofs cannot become a trusted package. */
import {cp,mkdir,readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import assert from 'node:assert/strict';
import {verifyPackage,sha} from './package-lib.mjs';
const source=resolve(process.argv[2]),expected=process.argv[3],out=resolve(process.argv[4]);await verifyPackage(source,expected);await mkdir(out);let checks=0;
await assert.rejects(()=>verifyPackage(source,undefined));checks++;
for(const changed of ['module','self-authored-proof','extra-file']){
 const copy=join(out,changed);await cp(source,copy,{recursive:true,errorOnExist:true,force:false});
 if(changed==='extra-file')await writeFile(join(copy,'unexpected.mjs'),'export default true;');
 else{
  const path=join(copy,'receiving.mjs');await writeFile(path,(await readFile(path,'utf8'))+'\n/* not the qualified artifact */\n');
  if(changed==='self-authored-proof'){const p=join(copy,'package-proof.json'),proof=JSON.parse(await readFile(p,'utf8'));proof.files_sha256['receiving.mjs']=sha(await readFile(path));await writeFile(p,JSON.stringify(proof,null,2)+'\n');}
 }
 await assert.rejects(()=>verifyPackage(copy,expected));checks++;
}
console.log(JSON.stringify({classification:'ACTUAL_ARTIFACT_INTEGRITY_NEGATIVE_CONTROLS',checks,expected_package_proof_sha256:expected,source_or_provider_effect:false}));
