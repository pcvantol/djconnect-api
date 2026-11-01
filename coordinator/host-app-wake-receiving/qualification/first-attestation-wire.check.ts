import {describe,it,expect} from 'vitest';
import vectors from './private-first-attestation-vectors.json';
import {decodeNativePolicy,assertionPolicyForNative} from '../native-policy';
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

describe('private v3 bounded first-enrollment policy DATA; no native admission',()=>{
 const category=(n:number)=>btoa(String.fromCharCode(n,0,0,0));
 const candidate=(values:unknown)=>{const {launch_validation_category_b64,...base}=vectors.policy_request;return {...base,profile:'host_wake_apple_properties_attestation_v3',allowed_launch_validation_categories_b64:values};};
 it.each([{values:[2,3]},{values:[3]}])('accepts an explicit first-enrollment category allowlist $values without claiming an observed category',({values})=>{
  const p=candidate(values.map(category));expect(decodeNativePolicy(p)).toEqual(p);expect(Object.hasOwn(p,'launch_validation_category_b64')).toBe(false);
 });
 it.each([{v:undefined},{v:null},{v:[]},{v:['AwAAAA==','AgAAAA==']},{v:['AwAAAA==','AwAAAA==']},{v:['AAAAAA==']},{v:['BgAAAA==']},{v:['AgAAAA==','AwAAAA==','BAAAAA==','BQAAAA==','BgAAAA==']},{v:['AwAAAA']},{v:'AwAAAA=='},{v:[3]}])('rejects malformed initial category set $v',({v})=>{expect(()=>decodeNativePolicy(candidate(v))).toThrow();});
 it('freezes the explicit custodian list independently of caller mutation',()=>{const list=[category(2),category(3)],p=decodeNativePolicy(candidate(list));list[0]=category(5);expect(p).toHaveProperty('allowed_launch_validation_categories_b64',[category(2),category(3)]);if(p.profile==='host_wake_apple_properties_attestation_v3')expect(Object.isFrozen(p.allowed_launch_validation_categories_b64)).toBe(true);});
 it('preserves exact v2 policy and rejects mixed-profile fields',()=>{expect(decodeNativePolicy(vectors.policy_request)).toEqual(vectors.policy_request);expect(()=>decodeNativePolicy({...vectors.policy_request,allowed_launch_validation_categories_b64:[category(3)]})).toThrow();expect(()=>decodeNativePolicy({...candidate([category(3)]),launch_validation_category_b64:category(3)})).toThrow();});
 it('creates only one observed category assertion pin, never an allowlist',()=>{const p=decodeNativePolicy(candidate([category(2),category(3)]));const pin=JSON.parse(assertionPolicyForNative(p,category(3)));expect(pin.launch_validation_category_b64).toBe(category(3));expect(Object.hasOwn(pin,'allowed_launch_validation_categories_b64')).toBe(false);expect(()=>assertionPolicyForNative(p,category(5))).toThrow();expect(()=>assertionPolicyForNative(decodeNativePolicy(vectors.policy_request),category(5))).toThrow();});
});
