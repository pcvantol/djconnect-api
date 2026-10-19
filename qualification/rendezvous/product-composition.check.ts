// Real product-module composition + five product DOs. cf values are fixtures, not edge provenance.
import {beforeAll,beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {env} from 'cloudflare:workers';
import {runInDurableObject} from 'cloudflare:test';
import {createProductRendezvousHandler,type ProductRendezvousEnv} from '../../src/rendezvous/composition';
import {deriveBudgetIdentity} from './allocation-budget';
import {base64Url} from '../../src/crypto';

const V='djc-rendezvous/1',ORIGIN='https://vibecast.tv';
const good=()=>({...env}) as unknown as ProductRendezvousEnv;
const keyId=btoa(String.fromCharCode(...new Uint8Array(32).fill(3)));
let jwk:Record<string,unknown>;
beforeAll(async()=>{
	const pair=await crypto.subtle.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']) as CryptoKeyPair;
	const {kty,e,n}=await crypto.subtle.exportKey('jwk',pair.publicKey) as JsonWebKey;jwk={kty,e,n};
});
let egress:ReturnType<typeof vi.fn>;
beforeEach(()=>{egress=vi.fn(async()=>{throw new Error('local_product_module_egress_denied');});vi.stubGlobal('fetch',egress);});
afterEach(()=>{expect(egress).not.toHaveBeenCalled();vi.restoreAllMocks();vi.unstubAllGlobals();});
const encoded=(bytes:Uint8Array)=>base64Url(bytes.buffer as ArrayBuffer);
type RequestOptions={origin?:string|null;ip?:string|null;cf?:unknown;headers?:Record<string,string>;url?:string;method?:string};
function request(path:string,body:unknown={v:V},options:RequestOptions={}){
	const headers=new Headers({'Content-Type':'application/json',...options.headers});
	if(options.origin!==null)headers.set('Origin',options.origin??ORIGIN);
	if(options.ip!==null)headers.set('CF-Connecting-IP',options.ip??'192.0.2.20');
	const result=new Request(options.url??'https://api.djconnect.dev/v1/rendezvous'+path,{method:options.method??'POST',headers,body:options.method==='OPTIONS'?undefined:JSON.stringify(body),cf:{colo:'AMS'}} as RequestInit);
	// Invalid cf types cannot be constructed by Request itself; shadow them only
	// for explicit malformed-object fixtures. None establishes edge provenance.
	if(Object.hasOwn(options,'cf'))Object.defineProperty(result,'cf',{value:options.cf});
	return result;
}
async function response(path:string,body:unknown={v:V},options:Parameters<typeof request>[2]={},bindings=good()){
	return createProductRendezvousHandler(bindings)(request(path,body,options));
}
function blockedNamespaces(bindings=good()){
	const calls=vi.fn(()=>{throw new Error('namespace_must_not_be_called');});
	for(const name of ['REQUEST_ADMISSION','ADMISSION_STATE','ALLOCATION_INDEX','ENROLLMENT_COORDINATOR','COMPOSED_TRANSACTIONS'] as const)bindings[name]={get:calls,idFromName:calls} as never;
	return {bindings,calls};
}
async function rejectsBeforeBody(bindings:ProductRendezvousEnv,req:Request){
	const read=vi.spyOn(req,'body','get').mockImplementation(()=>{throw new Error('body_must_not_be_read');});
	const result=await createProductRendezvousHandler(bindings)(req);
	expect(result.status).toBe(503);expect(await result.json()).toEqual({v:V,error:'service_unavailable'});expect(read).not.toHaveBeenCalled();
}

describe('internal product configuration and fixed identity',()=>{
	it('local egress guard intercepts an explicit QA-only positive control',async()=>{
		await expect(fetch('https://egress-denied.example.invalid/qualification')).rejects.toThrow('local_product_module_egress_denied');expect(egress).toHaveBeenCalledTimes(1);egress.mockClear();
	});
	it.each(['RENDEZVOUS_EDGE_POLICY','RENDEZVOUS_IP_HASH_KEY','RECEIPT_ACTIVE_KEY','COMPOSED_POLICY_ENABLED','REQUEST_POLICY_ENABLED','ALLOCATION_POLICY_ENABLED','INDEX_POLICY_ENABLED','ASSERTION_POLICY_ENABLED','ASSERTION_POLICY_EXPIRES_AT','ENROLLMENT_POLICY_REVISION'] as const)('missing %s rejects before body or namespace calls',async field=>{
		const {bindings,calls}=blockedNamespaces();delete bindings[field];await rejectsBeforeBody(bindings,request('/create'));expect(calls).not.toHaveBeenCalled();
	});
	it.each(['short','!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!',btoa('too-short'),btoa('x'.repeat(33))])('invalid HMAC material is rejected',async secret=>{
		const {bindings,calls}=blockedNamespaces();bindings.RENDEZVOUS_IP_HASH_KEY=secret;await rejectsBeforeBody(bindings,request('/create'));expect(calls).not.toHaveBeenCalled();
	});
	it.each<RequestOptions>([
		{cf:null},{cf:[]},{cf:'client-controlled'},
		{ip:null},{ip:'192.0.2.1, 192.0.2.2'},{ip:'192.000.2.1'},{ip:'192.0.2.1:443'},
		{ip:'[2001:db8::1]'},{ip:'not-an-address'},{ip:'2a06:98c0:3600::103'},
		{ip:'2A06:98C0:3600:0:0:0:0:0103'},{ip:'240.0.0.1'},{ip:'255.255.255.255'},
		{ip:'::ffff:240.0.0.1'},{ip:'0:0:0:0:0:ffff:f000:0001'},
		{headers:{'CF-Worker':''}},{headers:{'CF-Worker':'example.invalid'}},
		{ip:null,headers:{'X-Forwarded-For':'192.0.2.1','X-Real-IP':'192.0.2.1','True-Client-IP':'192.0.2.1','CF-Connecting-IPv6':'2001:db8::1'}},
	])('invalid identity fixture rejects before body or namespace calls %#',async options=>{
		const {bindings,calls}=blockedNamespaces();await rejectsBeforeBody(bindings,request('/create',{v:V},options));expect(calls).not.toHaveBeenCalled();
	});
	it('factory does not cache a prior valid configuration',async()=>{
		const bindings=good(),handler=createProductRendezvousHandler(bindings);bindings.RENDEZVOUS_EDGE_POLICY='disabled';
		expect((await handler(request('/create'))).status).toBe(503);
	});
	it('rejects caller-selected extra factory parameters',async()=>{
		const {bindings,calls}=blockedNamespaces();
		const handler=(createProductRendezvousHandler as Function)(bindings,()=>({minute:1,key:'caller-selected'}));
		expect((await handler(request('/create'))).status).toBe(503);expect(calls).not.toHaveBeenCalled();
	});
	it('rechecks configuration after HMAC before namespace or body access',async()=>{
		const {bindings,calls}=blockedNamespaces(),sign=crypto.subtle.sign.bind(crypto.subtle);
		vi.spyOn(crypto.subtle,'sign').mockImplementation(async(...args)=>{const result=await sign(...args);bindings.RENDEZVOUS_IP_HASH_KEY=btoa('z'.repeat(32));return result;});
		await rejectsBeforeBody(bindings,request('/create'));expect(calls).not.toHaveBeenCalled();
	});
	it.each([-1,60000])('rejects backward clock or minute crossing after HMAC: %i',async shift=>{
		const {bindings,calls}=blockedNamespaces(),sign=crypto.subtle.sign.bind(crypto.subtle),now=Date.now();
		vi.spyOn(crypto.subtle,'sign').mockImplementation(async(...args)=>{const result=await sign(...args);vi.spyOn(Date,'now').mockReturnValue(now+shift);return result;});
		await rejectsBeforeBody(bindings,request('/create'));expect(calls).not.toHaveBeenCalled();
	});
	it('normalizes equivalent IPv6 identities and does not expose raw IP',async()=>{
		const secret=good().RENDEZVOUS_IP_HASH_KEY!;
		const [a,b]=await Promise.all([deriveBudgetIdentity('2001:DB8:0:0:0:0:0:1',secret),deriveBudgetIdentity('2001:db8::1',secret)]);
		expect(a).toEqual(b);expect(Object.keys(a).sort()).toEqual(['key','minute']);expect(a.key).toMatch(/^[A-Za-z0-9_-]{43}$/);expect(JSON.stringify(a)).not.toContain('2001');
	});
});

describe('real five-DO product module',()=>{
	it('creates a temporary QR, inspects, reconnects, rejects wrong browser and cancels without native authority',async()=>{
		const claim=crypto.getRandomValues(new Uint8Array(32)),commitment=base64Url(await crypto.subtle.digest('SHA-256',claim));
		const sign=vi.spyOn(crypto.subtle,'sign');
		const created=await response('/create',{v:V,generation:1,browser_public_key:jwk,claim_commitment:commitment});
		expect(created.status).toBe(201);expect(sign).toHaveBeenCalledTimes(1);
		const tx=await created.json() as any;
		expect(tx.expires_at-tx.created_at).toBe(120000);expect(tx.qr_payload.transaction_id).toBe(tx.transaction_id);
		const scan={v:V,transaction_id:tx.transaction_id,generation:1,qr_capability:tx.qr_payload.qr_capability};
		expect((await response('/inspect',scan,{origin:null})).status).toBe(200);
		const browser={v:V,transaction_id:tx.transaction_id,generation:1,claim_secret:encoded(claim)};
		expect((await response('/poll',browser)).status).toBe(200);
		expect((await response('/consume',browser)).status).toBe(409);
		expect((await response('/cancel',{...browser,claim_secret:encoded(new Uint8Array(32).fill(7))})).status).toBe(401);
		const cancelled=await response('/cancel',browser);expect(cancelled.status).toBe(200);expect(await cancelled.json()).toEqual({v:V,state:'cancelled'});
		expect((await response('/consume',browser)).status).toBe(409);
	});
	it('default genuine verifier rejects malformed registration; original challenge persists and no key is installed',async()=>{
		const input={v:V,key_id:keyId,action:'register'};
		const first=await response('/attestation/challenge',input,{origin:null});expect(first.status).toBe(200);
		const challenge=await first.json() as any;
		const result=await response('/attestation/register',{v:V,key_id:keyId,challenge_id:challenge.challenge_id,attestation:encoded(new Uint8Array([0]))},{origin:null});
		expect(result.status).toBe(401);expect(await result.json()).toEqual({v:V,error:'invalid_sender_proof'});
		const retry=await response('/attestation/challenge',input,{origin:null});expect(await retry.json()).toEqual(challenge);
		const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(['development','ios-dev-qualification/1',keyId]))));
		const address=Array.from(digest,b=>b.toString(16).padStart(2,'0')).join('');const ns=good().ENROLLMENT_COORDINATOR;
		const rows=await runInDurableObject(ns.get(ns.idFromName('djc-rendezvous-key/1/'+address)),(_instance,state)=>state.storage.sql.exec<{n:number}>('SELECT COUNT(*) AS n FROM key_state').one().n);
		expect(rows).toBe(0);
	});
	it('wrong Origin retains existing wire403 and safe CORS',async()=>{
		const result=await response('/create',{v:V},{origin:'https://evil.example'});expect(result.status).toBe(403);expect(result.headers.has('Access-Control-Allow-Origin')).toBe(false);
	});
	it('unknown route preserves cheap invalid_request without namespace calls',async()=>{
		const {bindings,calls}=blockedNamespaces();const result=await response('/unknown',{v:V},{},bindings);expect(result.status).toBe(400);expect(await result.json()).toEqual({v:V,error:'invalid_request'});expect(calls).not.toHaveBeenCalled();
	});
	it.each(['http://api.djconnect.dev/v1/rendezvous/create','https://other.example/v1/rendezvous/create','https://api.djconnect.dev:444/v1/rendezvous/create','https://api.djconnect.dev/v1/rendezvous/create?extra=1','https://api.djconnect.dev/v1/rendezvous/create#fragment'])('noncanonical service URL is rejected cheaply: %s',async url=>{
		const {bindings,calls}=blockedNamespaces();const result=await response('/create',{v:V},{url},bindings);expect(result.status).toBe(400);expect(calls).not.toHaveBeenCalled();
	});
	it('proper preflight uses existing policy and credentials stay denied',async()=>{
		const preflight=await response('/create',undefined,{method:'OPTIONS',headers:{'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'Content-Type'}});
		expect(preflight.status).toBe(204);expect(preflight.headers.get('Access-Control-Allow-Origin')).toBe(ORIGIN);expect(preflight.headers.has('Access-Control-Allow-Credentials')).toBe(false);
		expect((await response('/create',{v:V},{headers:{Cookie:'example-only'}})).status).toBe(400);
	});
});
