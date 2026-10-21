// Fixed isolated QA entry. This source does not admit a native/device experiment.
import { createProductRendezvousHandler, type ProductRendezvousEnv } from './composition';
export { RequestAdmission, AllocationBudget, AllocationIndex, EnrollmentCoordinator, BudgetedTransactionCoordinator } from './coordinators';

declare const __DJC_QA_SOURCE_SHA__: string;
const SERVICE = 'https://api-vibecast-qa.djconnect.dev';
const BROWSER = 'https://qa.vibecast.tv';
// Missing current signed Apple profile and exact operational admission require a
// new reviewed source increment. No env/header/body value can enable this build.
const QA_ACTIVATION_REVIEWED = false as boolean;

export default {
 async fetch(request: Request, env: unknown): Promise<Response> {
  const url = new URL(request.url);
  const headers = new Headers({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Vary':'Origin'});
  const json = (value: unknown, status: number) => new Response(JSON.stringify(value), {status, headers});
  if (url.origin !== SERVICE || url.username || url.password) return json({error:'not_found'},404);
  if (request.method === 'GET' && url.href === SERVICE+'/health') return json({ok:true,service:'djconnect-api-vibecast-qa',release_sha:__DJC_QA_SOURCE_SHA__,activation_allowed:false},200);
  if (url.pathname !== '/v1/rendezvous' && !url.pathname.startsWith('/v1/rendezvous/')) return json({error:'not_found'},404);
  if (request.headers.get('Origin') === BROWSER) headers.set('Access-Control-Allow-Origin',BROWSER);
  if (!QA_ACTIVATION_REVIEWED) return json({v:'djc-rendezvous/1',error:'service_unavailable'},503);
  return createProductRendezvousHandler(env as ProductRendezvousEnv)(request);
 }
};
