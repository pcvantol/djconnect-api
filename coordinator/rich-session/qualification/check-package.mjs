import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';
const out=process.argv[2],sha=b=>createHash('sha256').update(b).digest('hex');
const proof=JSON.parse(await readFile(join(out,'source-package.json')));assert.equal(sha(await readFile(join(out,'profile-data.mjs'))),proof.module_sha256);
const api=await import(pathToFileURL(join(out,'profile-data.mjs')));
assert.equal(api.CONTRACT_SHA256,proof.contract_sha256);assert.equal(api.PROFILE,'djconnect-session-rich-v1');
const receipt=JSON.parse(await readFile(join(out,'apple-fixtures/encoder-fixture-receipt.json')));
for(const [name,v]of Object.entries(receipt.fixture_inventory)){const bytes=await readFile(join(out,'apple-fixtures',name));assert.equal(bytes.length,v.bytes);assert.equal(sha(bytes),v.sha256);}
const attr=await readFile(join(out,'apple-fixtures/attributes_original_uuid.json'),'utf8'),state=await readFile(join(out,'apple-fixtures/state_rich_unicode_escaping.json'),'utf8');
const carrier=JSON.stringify({schema_version:1,profile_id:api.PROFILE,attributes_utf8_b64u:Buffer.from(attr).toString('base64url'),content_state_utf8_b64u:Buffer.from(state).toString('base64url'),source_observed_at_ms:1800000000125,source_expires_at_ms:1800000030125});
const data=api.decodeRichCarrier(carrier);assert.equal(data.attributes_utf8,attr);assert.equal(data.content_state_utf8,state);assert.equal(data.classification,'RICH_SESSION_PROFILE_DATA_ONLY');
const expected={attributes_utf8:attr,content_state_utf8:state,source_observed_at_ms:1800000000125,source_expires_at_ms:1800000030125};assert.equal(api.checkOriginalRichData(data,expected),data);
for(const event of ['update','end']){const result=api.prepareApnsData(data,event,1800000000125,event==='end'?1800000000000:undefined);assert.ok(result.body_utf8.includes('"content-state":'+state+',"stale-date":'));assert.equal(result.body_bytes,Buffer.byteLength(result.body_utf8));assert.equal(JSON.parse(result.body_utf8).aps.event,event);}
// Integer fields must reject original fractional/exponent tokens before Number rounding.
for(const token of ['999.999999999999999999999','1000.000000000000000000001','1e3']){
 const raw=carrier.replace('1800000000125','0').replace('1800000030125',token);
 assert.throws(()=>api.decodeRichCarrier(raw));
}
assert.throws(()=>api.prepareApnsData({...data},'update',1800000000125));assert.throws(()=>api.createProductionRichProfile());
const utc=JSON.parse(await readFile(join(out,'utc-rational-cases.json')));for(const c of utc.cases){const r=api.projectOriginalUtcBoundsData(c.original_observed_seconds,c.original_expiry_seconds);assert.equal(r.source_observed_at_ms,c.expected_observed_ms);assert.equal(r.source_expires_at_ms,c.expected_expiry_ms);}
const result={actual_packaged_ESM:true,module_sha256:proof.module_sha256,original_Apple_file_hashes_verified:Object.keys(receipt.fixture_inventory).length,exact_UTC_reference_cases:utc.cases.length,original_fragments_preserved:true,update_and_end_DATA:true,forged_handle_rejected:true,production_factory_closed:true,original_integer_token_regressions:3,native_or_provider_admission:false,actual_effects:false};
await writeFile(join(out,'package-check.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));
