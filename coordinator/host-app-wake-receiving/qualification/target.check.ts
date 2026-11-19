import {describe,it,expect} from 'vitest';
import vectors from './private-target-ports-vectors.json';
import {checkTargetCorrelation,decodeTargetReply} from '../target-transport';
import {decode, type Kind} from '../../host-app-wake/wire';
import {decodeNativeOriginal} from '../wire';
import {decodePrivateError} from '../server-reply';
import {canonical} from '../../../src/surface-push/wire';
import {sha256Hex} from '../../../src/crypto';
const original=decodeNativeOriginal(vectors.original);
describe('private target SOURCE181 body and reply DATA, independent Python synthetic vectors only',()=>{
 it.each(vectors.cases)('joins $kind $status unchanged Source181 reply to exact operation, retained purpose and private correlation',async row=>{
  const input=decode(row.kind as Kind,row.request),hash=await sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST',row.path,input]));expect(hash).toBe(row.request_sha256);checkTargetCorrelation(row.reply_headers['X-DJConnect-Host-Wake-Request-SHA256'],hash);
  expect(decodeTargetReply(row.reply,input,original,vectors.private_purpose_id)).toEqual(row.reply);
 });
 it.each(vectors.cases)('rejects $kind $status wrong-purpose, wrong-operation, extra and substituted reply fields',row=>{
  const input=decode(row.kind as Kind,row.request);for(const change of [{purpose_id:'other-purpose'},{operation_id:'different-operation'},{credential:'never-returned'},{expires_at_ms:original.original_wake_expires_at_ms+1}])expect(()=>decodeTargetReply({...row.reply,...change},input,original,vectors.private_purpose_id)).toThrow();
 });
 it('requires a single exact response correlation digest and never recovers permission from the digest',()=>{
  const hash=vectors.cases[0].request_sha256;for(const wrong of [null,'',hash+', '+hash,'A'.repeat(64),'f'.repeat(64)])expect(()=>checkTargetCorrelation(wrong,hash)).toThrow();
 });
 it('keeps terminal source state ahead of a retained historical registration outcome',()=>{
  const row=vectors.cases.find(v=>v.kind==='revoke')!,out=decodeTargetReply(row.reply,decode('revoke',row.request),original,vectors.private_purpose_id);expect(out.state).toBe('withdrawn');expect(out.operation_state).toBe('registered');
 });
 it.each(vectors.errors)('uses existing closed receiving errors with HTTP$status, without a Source181 success or capability',row=>{
  expect(decodePrivateError(row.status,row.body)).toEqual(row.body);expect(()=>decodePrivateError(row.status,{...row.body,credential:'not-recoverable'})).toThrow();
 });
});
