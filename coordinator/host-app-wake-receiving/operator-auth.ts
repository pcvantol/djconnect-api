/** Existing actual API custodian channel, explicitly HMAC-only here. */
import {requireAdminAuth} from '../../src/auth';
import type {AppEnv} from '../../src/types';
import {need} from '../host-app-wake/wire';
import {decodeNativePolicy,decodeNativePolicyWithdrawal,OPERATOR_NATIVE_POLICY,OPERATOR_NATIVE_WITHDRAW} from './native-policy';
import {boundedJson,decodeOperatorAuthorization,decodeOperatorWithdrawal,OPERATOR_AUTHORIZE,OPERATOR_WITHDRAW} from './wire';
export async function authenticateOperator(request:Request,env:AppEnv,kind:'authorize'|'withdraw'|'native_policy'|'native_policy_withdraw'){
 const path=kind==='authorize'?OPERATOR_AUTHORIZE:kind==='withdraw'?OPERATOR_WITHDRAW:kind==='native_policy'?OPERATOR_NATIVE_POLICY:OPERATOR_NATIVE_WITHDRAW,url=new URL(request.url);
 need(request.method==='POST'&&url.pathname===path&&!url.search&&!url.hash,'host_wake_operator_route',404);
 need(!request.headers.has('origin')&&!request.headers.has('cookie'),'host_wake_server_transport',403);
 // requireAdminAuth also supports shared-secret Bearer. Do not admit that
 // fallback in this explicitly selected HMAC-only receiving grammar.
 need(!request.headers.has('authorization')&&request.headers.has('x-djconnect-timestamp')&&request.headers.has('x-djconnect-signature'),'host_wake_operator_hmac_required',401);
 const body=await boundedJson(request);
 const authRequest=new Request(request.url,{method:'POST',headers:request.headers,body:body.raw});
 await requireAdminAuth(authRequest,env);
 // Existing HMAC signs timestamp+'.'+exact body, not URL. These signed body
 // fields bind the actual method/path/action/version explicitly, after auth.
 const value=kind==='authorize'?decodeOperatorAuthorization(body.value):kind==='withdraw'?decodeOperatorWithdrawal(body.value):kind==='native_policy'?decodeNativePolicy(body.value):decodeNativePolicyWithdrawal(body.value);
 need(value.route===url.pathname&&value.method===request.method,'host_wake_operator_route_binding',403);
 return value;
}
