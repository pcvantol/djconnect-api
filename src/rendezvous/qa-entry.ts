// Fixed isolated QA entry. This source does not admit a native/device experiment.
import { createProductRendezvousHandler, type ProductRendezvousEnv } from './composition';
export { RequestAdmission, AllocationBudget, AllocationIndex, EnrollmentCoordinator, BudgetedTransactionCoordinator } from './coordinators';

declare const __DJC_QA_SOURCE_SHA__: string;
const SERVICE = 'https://api-vibecast-qa.djconnect.dev';
const BROWSER = 'https://qa.vibecast.tv';
// Missing current signed Apple profile and exact operational admission require a
// new reviewed source increment. No env/header/body value can enable this build.
const QA_ACTIVATION_REVIEWED = false as boolean;
type QaWindow = Readonly<{ startsAt: number; endsAt: number }>;
// A future reviewed build supplies the intersection of the Apple, Core and test windows.
const QA_WINDOW: QaWindow | null = null;
const TRANSACTION_LIFETIME_MS = 120_000;

function activeWindow(window: QaWindow | null, now: number): window is QaWindow {
 return window !== null
  && Number.isSafeInteger(window.startsAt) && window.startsAt >= 0
  && Number.isSafeInteger(window.endsAt) && window.endsAt - window.startsAt > TRANSACTION_LIFETIME_MS
  && now >= window.startsAt && now < window.endsAt;
}

function selectWindow(window: QaWindow | null, now: number): QaWindow | null {
 return QA_ACTIVATION_REVIEWED && activeWindow(window, now) ? window : null;
}

function usableCreateResponse(value: unknown, now: number, window: QaWindow): boolean {
 if (!value || typeof value !== 'object') return false;
 const { created_at: created, expires_at: expires } = value as Record<string, unknown>;
 return typeof created === 'number' && Number.isSafeInteger(created)
  && typeof expires === 'number' && Number.isSafeInteger(expires)
  && created >= window.startsAt && created <= now && expires > now
  && expires - created === TRANSACTION_LIFETIME_MS && expires < window.endsAt;
}

export default {
 async fetch(request: Request, env: unknown): Promise<Response> {
  const url = new URL(request.url);
  const headers = new Headers({'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Vary':'Origin'});
  const json = (value: unknown, status: number) => new Response(JSON.stringify(value), {status, headers});
  if (url.origin !== SERVICE || url.username || url.password) return json({error:'not_found'},404);
  const startedAt = Date.now();
  const window = selectWindow(QA_WINDOW, startedAt);
  if (request.method === 'GET' && url.href === SERVICE+'/health') return json({ok:true,service:'djconnect-api-vibecast-qa',release_sha:__DJC_QA_SOURCE_SHA__,activation_allowed:window!==null},200);
  if (url.pathname !== '/v1/rendezvous' && !url.pathname.startsWith('/v1/rendezvous/')) return json({error:'not_found'},404);
  if (request.headers.get('Origin') === BROWSER) headers.set('Access-Control-Allow-Origin',BROWSER);
  const unavailable = () => json({v:'djc-rendezvous/1',error:'service_unavailable'},503);
  const createsPairing = request.method === 'POST' && url.pathname === '/v1/rendezvous/create';
  if (!window || (createsPairing && startedAt >= window.endsAt - TRANSACTION_LIFETIME_MS)) return unavailable();
  const response = await createProductRendezvousHandler(env as ProductRendezvousEnv)(request);
  const stillActive = (now: number) => now >= startedAt && activeWindow(window, now);
  if (!stillActive(Date.now())) return unavailable();
  if (createsPairing && response.status === 201) {
   try {
    const descriptor: unknown = await response.clone().json();
    const now = Date.now();
    if (!stillActive(now) || !usableCreateResponse(descriptor, now, window)) return unavailable();
   } catch {
    return unavailable();
   }
  }
  return response;
 }
};
