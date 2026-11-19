import {describe,it,expect} from 'vitest';
import vectors from './native-transcript-vectors.json';
import {nativeSigningData,parseNativeTranscript,checkNativeChallenge,checkNativeToken,nativeTokenSha256,decodeNativeOriginal,decodeNativeChallenge} from '../wire';
const {original:o,challenge:c,canonical_utf8:canonical}=vectors;
const bytes=Uint8Array.from(vectors.native_token_hex.match(/../g)!,x=>Number.parseInt(x,16));
describe('shared public native transcript, Python independent DATA vectors',()=>{
 it('matches exact Python canonical bytes, LF domain and SHA256',async()=>{
  const d=nativeSigningData(o,c);expect(d.canonical_utf8).toBe(canonical);
  expect([...d.client_data].map(x=>x.toString(16).padStart(2,'0')).join('')).toBe(vectors.client_data_hex);
  expect((await checkNativeChallenge(o,c,canonical,vectors.client_data_sha256)).client_data_sha256).toBe(vectors.client_data_sha256);
  expect(parseNativeTranscript(canonical)).toEqual({original:o,challenge:c});
 });
 it('hashes original native bytes rather than their hexadecimal text',async()=>{
  expect(await nativeTokenSha256(bytes)).toBe(vectors.native_token_sha256);await checkNativeToken(o,bytes);
  expect(vectors.native_token_sha256).not.toBe(vectors.wrong_hex_text_token_sha256);
  await expect(checkNativeToken(o,new TextEncoder().encode(vectors.native_token_hex))).rejects.toThrow();
 });
 it.each(['authorization_id','core_install_token_record_id','purpose_id','proof_job_id','native_key_ref','capability'])('excludes private API %s',key=>{
  expect(()=>decodeNativeOriginal({...o,[key]:'private'})).toThrow();expect(canonical.includes('"'+key+'"')).toBe(false);
 });
 it.each([
  canonical.replace('"revision":1','"revision":1.0'),canonical.replace('"revision":1','"revision":1e0'),
  canonical.replace('"revision":1','"revision":-0'),canonical.replace('"revision":1','"revision":9007199254740992'),
  ' '+canonical,'\uFEFF'+canonical,canonical+'\n',JSON.stringify({original:o,challenge:c},null,2),
  canonical.replace('"revision":1','"revision":1,"\\u0072evision":1'),
  canonical.replace('"original"','"\\u006friginal"'),
 ])('rejects ambiguous or noncanonical raw transcript %s',text=>{expect(()=>parseNativeTranscript(text)).toThrow();});
 it('accepts reordered object DATA only by producing the same canonical transcript',()=>{
  expect(nativeSigningData(Object.fromEntries(Object.entries(o).reverse()),c).canonical_utf8).toBe(canonical);
  expect(()=>parseNativeTranscript(JSON.stringify({original:o,challenge:c}))).toThrow();
 });
 it.each(['nonce','target','expiry','semantic-operation','challenge-identity'])('refuses substituted %s against original advertised bytes',async field=>{
  const original={...o},challenge={...c};
  if(field==='nonce')challenge.nonce_b64url='B'+'A'.repeat(42);
  if(field==='target')original.target={...o.target,installation_id:'other'};
  if(field==='expiry')challenge.expires_at_ms--;
  if(field==='semantic-operation')original.operation_id='33333333-3333-4333-8333-333333333333';
  if(field==='challenge-identity')challenge.challenge_id='44444444-4444-4444-8444-444444444444';
  await expect(checkNativeChallenge(original,challenge,canonical,vectors.client_data_sha256)).rejects.toThrow();
 });
 it('distinguishes actual LF prefix from literal backslash-n',async()=>{
  const suffix=new TextEncoder().encode(canonical),prefix=new TextEncoder().encode('DJC-HOST-APP-WAKE-TARGET-REGISTER-V1\\n');
  const raw=new Uint8Array(prefix.length+suffix.length);raw.set(prefix);raw.set(suffix,prefix.length);
  const sha=[...new Uint8Array(await crypto.subtle.digest('SHA-256',raw))].map(x=>x.toString(16).padStart(2,'0')).join('');
  expect(sha).not.toBe(vectors.client_data_sha256);
 });
 it('leaves standard-base64 slash values literal, never escaped or base64url converted',()=>{
  const value={...o,native_key_id_b64:'//8='};const encoded=nativeSigningData(value,c).canonical_utf8;
  expect(encoded.includes('"native_key_id_b64":"//8="')).toBe(true);
  expect(()=>parseNativeTranscript(encoded.replace('//8=','\\/\\/8='))).toThrow();
  expect(()=>decodeNativeOriginal({...value,native_key_id_b64:'__8='})).toThrow();
 });
 it.each(['','Zg','Zh==','Zg__','é===','Zg==\n'])('rejects noncanonical standard-base64 SDK key data %s',native_key_id_b64=>{
  expect(()=>decodeNativeOriginal({...o,native_key_id_b64})).toThrow();
 });
 it('keeps semantic-operation and challenge UUIDs distinct fields and bounded v4 DATA',()=>{
  expect(()=>decodeNativeOriginal({...o,operation_id:'not-a-uuid'})).toThrow();
  expect(()=>decodeNativeChallenge({...c,challenge_id:'not-a-uuid'},decodeNativeOriginal(o))).toThrow();
 });
});
