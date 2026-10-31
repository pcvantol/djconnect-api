import {describe,it,expect} from 'vitest';
import vectors from './private-first-attestation-vectors.json';
import {decodeNativePolicy} from '../native-policy';
import {decodeResolve,decodeResolvedAuthorization} from '../authorization-resolve';
import {decodeNativeOriginal} from '../wire';
import {decodeServer,type ServerRoute} from '../server-wire';
import {decodePrivateReply,decodePrivateError} from '../server-reply';
import {sha256Hex} from '../../../src/crypto';
import {canonical} from '../../../src/surface-push/wire';
const original=decodeNativeOriginal(vectors.original);
describe('first-attestation protocol SHAPES ONLY; modeled positive replies are NOT vendor proof or native admission',()=>{
 it('parses only the explicit custodian policy and pending resolve DATA, with unchanged request correlation',async()=>{
  expect(decodeNativePolicy(vectors.policy_request)).toEqual(vectors.policy_request);const req=decodeResolve(vectors.resolve.request);expect(await sha256Hex(canonical(req.scope))).toBe(vectors.resolve.scope_sha256);expect(decodeResolvedAuthorization(vectors.resolve.request_sha256,vectors.resolve.scope_sha256,vectors.resolve.reply)).toEqual(vectors.resolve.reply);
 });
 it.each(vectors.cases)('decodes the $route first-attestation DATA shape without interpreting its placeholder proof as genuine',async row=>{
  const route=row.route as ServerRoute,input=decodeServer(route,row.request);expect(await sha256Hex(canonical(['DJC-HOST-WAKE-API-REQUEST-V1','POST','/v1/push/host-app-wake/'+route,input]))).toBe(row.request_sha256);expect(await decodePrivateReply(route,input,original,row.request_sha256,row.reply,'app_attest_attestation')).toEqual(row.reply);
 });
 it('retains the immutable attestation kind and does not substitute assertion from app-local key existence',async()=>{
  const row=vectors.cases.find(v=>v.route==='native/challenge')!;await expect(decodePrivateReply('native/challenge',decodeServer('native/challenge',row.request),original,row.request_sha256,row.reply,'app_attest_assertion')).rejects.toThrow();
 });
 it('keeps the actual placeholder-proof rejection distinct from modeled native_verified shape vectors',()=>{
  expect(decodePrivateError(vectors.invalid_proof_runtime_expectation.status,vectors.invalid_proof_runtime_expectation.body)).toEqual(vectors.invalid_proof_runtime_expectation.body);
 });
});
