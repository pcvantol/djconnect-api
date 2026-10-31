import {describe,it,expect} from 'vitest';
import vectors from './private-server-reply-vectors.json';
import resolveVector from './private-resolve-vectors.json';
import {decodeResolve,decodeResolvedAuthorization} from '../authorization-resolve';
import {canonical} from '../../../src/surface-push/wire';
import {sha256Hex} from '../../../src/crypto';
import {decodePrivateReply,decodePrivateError} from '../server-reply';
import {decodeServer,type ServerRoute} from '../server-wire';
import {decodeNativeOriginal} from '../wire';
const original=decodeNativeOriginal(vectors.original);
describe('six owning private API reply ports, synthetic independent Python vectors only',()=>{
 it.each(vectors.cases)('accepts exact bound $route reply without inventing original authority',async row=>{
  const route=row.route as ServerRoute,input=decodeServer(route,row.request);expect(await decodePrivateReply(route,input,original,row.request_sha256,row.reply,'app_attest_assertion')).toEqual(row.reply);
 });
 it.each(vectors.cases)('rejects cross-request or extra-field $route replies',async row=>{
  const route=row.route as ServerRoute,input=decodeServer(route,row.request);await expect(decodePrivateReply(route,input,original,'f'.repeat(64),row.reply,'app_attest_assertion')).rejects.toThrow();await expect(decodePrivateReply(route,input,original,row.request_sha256,{...row.reply,success:true},'app_attest_assertion')).rejects.toThrow();
 });
 it('never returns or recovers a capability from status/withdraw/native replies',async()=>{
  for(const row of vectors.cases.filter(r=>r.route!=='issuer/issue'))await expect(decodePrivateReply(row.route as ServerRoute,decodeServer(row.route as ServerRoute,row.request),original,row.request_sha256,{...row.reply,credential:'djchw_'+'A'.repeat(43)},'app_attest_assertion')).rejects.toThrow();
 });
 it('keeps native_verified distinct from target registration, and withdrawal strictly negative',async()=>{
  for(const row of vectors.cases.filter(r=>r.route==='native/complete'||r.route==='native/status'||r.route==='issuer/withdraw'))await expect(decodePrivateReply(row.route as ServerRoute,decodeServer(row.route as ServerRoute,row.request),original,row.request_sha256,{...row.reply,state:'registered'},'app_attest_assertion')).rejects.toThrow();
 });
 it('does not infer native proof kind from the reply or a local journal when retained prepare context is absent/different',async()=>{
  const row=vectors.cases.find(r=>r.route==='native/challenge')!,input=decodeServer('native/challenge',row.request);await expect(decodePrivateReply('native/challenge',input,original,row.request_sha256,row.reply)).rejects.toThrow();await expect(decodePrivateReply('native/challenge',input,original,row.request_sha256,row.reply,'app_attest_attestation')).rejects.toThrow();
 });
 it('does not imply rotation or change the original expiry in a winning issuer reply',async()=>{
  const row=vectors.cases[0],input=decodeServer('issuer/issue',row.request);for(const change of [{registration_mode:'rotate'},{expires_at_ms:original.original_wake_expires_at_ms+1},{credential_state:'unavailable'}])await expect(decodePrivateReply('issuer/issue',input,original,row.request_sha256,{...row.reply,...change})).rejects.toThrow();
 });
 it('joins independent resolve request and role-owned metadata hashes without inventing a parent',async()=>{
  const body=decodeResolve(resolveVector.request);expect(await sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',resolveVector.path,body]))).toBe(resolveVector.request_sha256);expect(await sha256Hex(canonical(body.scope))).toBe(resolveVector.scope_sha256);expect(decodeResolvedAuthorization(resolveVector.request_sha256,resolveVector.scope_sha256,resolveVector.reply)).toEqual(resolveVector.reply);
 });
 it('rejects policy metadata injection, extra replies, malformed policy hashes and substituted resolve correlations',()=>{
  expect(()=>decodeResolve({...resolveVector.request,scope:{...resolveVector.request.scope,identity_policy_sha256:'f'.repeat(64)}})).toThrow();
  for(const change of [{credential:'not-recoverable'},{identity_policy_sha256:'invalid'},{request_sha256:'f'.repeat(64)}])expect(()=>decodeResolvedAuthorization(resolveVector.request_sha256,resolveVector.scope_sha256,{...resolveVector.reply,...change})).toThrow();
 });
 it('decodes only the closed versioned allowlisted private error body',()=>{
  expect(decodePrivateError(vectors.error.http_status,vectors.error.body)).toEqual(vectors.error.body);expect(()=>decodePrivateError(409,{...vectors.error.body,exception:'private-key-data'})).toThrow();expect(()=>decodePrivateError(409,{...vectors.error.body,error:'arbitrary_exception'})).toThrow();
 });
});
