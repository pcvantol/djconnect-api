// Internal product-module composition only. The root public Worker stays compiled503.
import {createRequestBudgetedHandler,REQUEST_POLICY,REQUEST_LANES,type RequestEnv} from '../../qualification/rendezvous/request-admission';
import {COMPOSED_POLICY,type ComposedEnv} from '../../qualification/rendezvous/composed-http';
import {deriveBudgetIdentity,normalizeBudgetIp,BUDGET_POLICY} from '../../qualification/rendezvous/allocation-budget';
import {INDEX_POLICY} from '../../qualification/rendezvous/allocation-index';
import {validReceiptActiveKey} from '../../qualification/rendezvous/receipt-key-store';
import type {EnrollmentEnv} from '../../qualification/rendezvous/enrollment-key-state';

export type ProductRendezvousEnv=ComposedEnv&RequestEnv&EnrollmentEnv&{
	ALLOCATION_POLICY_ENABLED?:string;INDEX_POLICY_ENABLED?:string;
	RENDEZVOUS_EDGE_POLICY?:string;RENDEZVOUS_IP_HASH_KEY?:string;
};
const fields=['COMPOSED_POLICY_ENABLED','REQUEST_POLICY_ENABLED','RENDEZVOUS_CAPACITY_POLICY','ALLOCATION_POLICY_ENABLED','INDEX_POLICY_ENABLED','ASSERTION_POLICY_ENABLED','ASSERTION_POLICY_EXPIRES_AT','ENROLLMENT_POLICY_REVISION','RECEIPT_ACTIVE_KEY','RECEIPT_PREVIOUS_KEY','RENDEZVOUS_EDGE_POLICY','RENDEZVOUS_IP_HASH_KEY','REQUEST_ADMISSION','ADMISSION_STATE','ALLOCATION_INDEX','ENROLLMENT_COORDINATOR','COMPOSED_TRANSACTIONS'] as const;
const namespaces=['REQUEST_ADMISSION','ADMISSION_STATE','ALLOCATION_INDEX','ENROLLMENT_COORDINATOR','COMPOSED_TRANSACTIONS'] as const;
const closedHandler=createRequestBudgetedHandler();
const need:(value:unknown)=>asserts value=value=>{if(!value)throw new Error('service_unavailable');};

function snapshot(env:ProductRendezvousEnv){
	need(env&&typeof env==='object');
	need(env.RENDEZVOUS_CAPACITY_POLICY===undefined||env.RENDEZVOUS_CAPACITY_POLICY==='private-household/1');
	need(env.RENDEZVOUS_EDGE_POLICY==='djc-direct-edge-identity/1-candidate');
	need(env.COMPOSED_POLICY_ENABLED===COMPOSED_POLICY&&env.REQUEST_POLICY_ENABLED===REQUEST_POLICY&&env.ALLOCATION_POLICY_ENABLED===BUDGET_POLICY&&env.INDEX_POLICY_ENABLED===INDEX_POLICY);
	const until=Number(env.ASSERTION_POLICY_EXPIRES_AT);
	need(env.ASSERTION_POLICY_ENABLED==='ios-dev-qualification/1'&&Number.isSafeInteger(until)&&Date.now()<until);
	need(typeof env.ENROLLMENT_POLICY_REVISION==='string'&&env.ENROLLMENT_POLICY_REVISION.length>0&&env.ENROLLMENT_POLICY_REVISION.length<=128);
	need(validReceiptActiveKey(env));
	const secret=env.RENDEZVOUS_IP_HASH_KEY;
	need(typeof secret==='string'&&secret.length===44);
	const bytes=atob(secret);need(bytes.length===32&&btoa(bytes)===secret);
	for(const name of namespaces)need(typeof env[name]?.get==='function'&&typeof env[name]?.idFromName==='function');
	return fields.map(name=>env[name]);
}

function directEdgeIp(request:Request):string{
	const url=new URL(request.url),path=url.pathname.slice('/v1/rendezvous'.length);
	need(Object.hasOwn(REQUEST_LANES,path)&&url.href==='https://api.djconnect.dev/v1/rendezvous'+path);
	need(request.cf&&typeof request.cf==='object'&&!Array.isArray(request.cf));
	need(!request.headers.has('CF-Worker'));
	const raw=request.headers.get('CF-Connecting-IP');need(typeof raw==='string'&&raw===raw.trim());
	const ip=normalizeBudgetIp(raw);
	need(ip!=='2a06:98c0:3600::103');
	if(!ip.includes(':'))need(Number(ip.split('.')[0])<240);
	else if(ip.startsWith('::ffff:'))need(parseInt(ip.slice(7).split(':')[0],16)<0xf000);
	return ip;
}

/** No caller-selected identity, provider, namespace or cryptographic policy. */
export function createProductRendezvousHandler(env:ProductRendezvousEnv){
	const validArity=arguments.length===1;
	return async(request:Request):Promise<Response>=>{
		try{
			need(validArity);
			const before=snapshot(env);
			return await createRequestBudgetedHandler(env,async incoming=>{
				const startedAt=Date.now(),ip=directEdgeIp(incoming);
				const identity=await deriveBudgetIdentity(ip,env.RENDEZVOUS_IP_HASH_KEY!);
				const after=snapshot(env);
				need(before.every((value,index)=>value===after[index]));
				need(Date.now()>=startedAt&&identity.minute===Math.floor(startedAt/60000)&&identity.minute===Math.floor(Date.now()/60000));
				return identity;
			})(request);
		}catch{return closedHandler(request);}
	};
}
