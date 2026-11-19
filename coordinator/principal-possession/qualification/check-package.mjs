// Functional verification of the actual delivered ESM using public software vectors.
import {readFile,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
const dir=resolve(process.argv[2]),modulePath=join(dir,'possession-data.mjs');
const proof=JSON.parse(await readFile(join(dir,'source-package.json')));
if(createHash('sha256').update(await readFile(modulePath)).digest('hex')!==proof.module_sha256)throw Error('module hash mismatch');
const library=await import(pathToFileURL(modulePath).href);
if(JSON.stringify(Object.keys(library).sort())!==JSON.stringify(['PossessionDataInputError','verifyPossessionData']))throw Error('unexpected exports');
const v=JSON.parse(await readFile(join(dir,'public-vectors.json')));
const run=s=>library.verifyPossessionData(v.body,v.body,s);
const first=await run(v.signature_b64url),alias=await run(v.opposite_s_signature_b64url);
if(first?.classification!=='KEY_POSSESSION_DATA_ONLY'||first.body_sha256!==v.body_sha256||first.signing_input_sha256!==v.signing_input_sha256||
  !Object.isFrozen(first)||JSON.stringify(first)!==JSON.stringify(alias))throw Error('packaged DATA mismatch');
for(const wrong of v.wrong_domain_signatures)if(await run(wrong.signature_b64url)!==null)throw Error('wrong domain accepted');
let rejected=false;
try {await library.verifyPossessionData(v.r1_encoding_body,v.body,v.signature_b64url);}
catch(error) {if(!(error instanceof library.PossessionDataInputError)||error.code!=='transcript_mismatch')throw error;rejected=true;}
if(!rejected)throw Error('expected transcript not enforced');
const observed={classification:'PACKAGED_DATA_MODULE_HOST_CHECK_NOT_ADMISSION',node:process.version,module_sha256:proof.module_sha256,
  exports_data_only:true,real_public_fixture_verifies:true,opposite_S_same_original_DATA:true,wrong_domains_rejected:true,
  original_expected_mismatch_rejected:true,frozen_result:true,key_generation:false,signing:false,registration:false,deployed:false};
await writeFile(join(dir,'package-check.json'),JSON.stringify(observed,null,2)+'\n');console.log(JSON.stringify(observed));
