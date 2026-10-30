import {checkOriginalRichData, decodeRichCarrier, prepareApnsData, type OriginalRichData} from '../rich-session/profile-data';

/** Server-only composition ports. These are not request JSON, a permission wire,
 * or a way to turn codec DATA into admission. No default ports or network. */
export interface ReservedRichDelivery {
  readonly operation: string;
  readonly carrier: string;
  readonly original: OriginalRichData;
  readonly event: 'update' | 'end';
  readonly dismissalAt?: number;
  readonly token: string;
  readonly topic: string;
  readonly environment: 'sandbox' | 'production';
  readonly expiresAt: number;
  /** Actual owner must check original permission, relay/field rights, target,
   * installation, operation, cancellation, clock and withdrawal synchronously. */
  assertCurrent(): void;
}
export type ProviderObservation = Readonly<{outcome:'provider_accepted'|'provider_rejected'|'outcome_unknown'|'not_sent'; status?:number}>;
export interface RichDeliveryPorts {
  /** Authenticate original wire using selected custody and consume/reserve its
   * original operation atomically BEFORE provider authorization. Never remint. */
  admitAndReserve(attempt: unknown, signal: AbortSignal): Promise<ReservedRichDelivery>;
  authorizeProvider(): Promise<string>;
  /** Durable once-only marker; a lost reply MUST prevent a later outbound retry. */
  markDispatch(operation: string, requestSha256: string, expiresAt: number): Promise<'marked'|'already_attempted'>;
  /** Persist the observation without restoring authority or extending a lease. */
  finish(operation: string, observation: ProviderObservation): Promise<void>;
  now(): number;
  fetcher: typeof fetch;
}
export type DeliveryResult = Readonly<{outcome:'provider_accepted'|'provider_rejected'|'outcome_unknown'|'not_sent'|'already_attempted'; status?:number}>;
export class RichDeliveryError extends Error { constructor(readonly code:string){super(code);} }
function need(value:unknown,code='rich_delivery_invalid'):asserts value {if(!value)throw new RichDeliveryError(code);}
const integer=(value:unknown):value is number=>typeof value==='number'&&Number.isSafeInteger(value)&&value>=0&&!Object.is(value,-0);
const own=(object:object,key:string):unknown=>{
  const d=Object.getOwnPropertyDescriptor(object,key);need(d&&Object.hasOwn(d,'value'));return d.value;
};
const text=(value:unknown,pattern:RegExp,max:number):string=>{need(typeof value==='string'&&value.length<=max&&pattern.test(value));return value;};

export function createRichDeliveryAdapter(ports:RichDeliveryPorts){
  need(ports&&typeof ports==='object','rich_delivery_ports_missing');
  const admit=ports.admitAndReserve,authorize=ports.authorizeProvider,mark=ports.markDispatch,finish=ports.finish,time=ports.now,fetcher=ports.fetcher;
  need([admit,authorize,mark,finish,time,fetcher].every(x=>typeof x==='function'),'rich_delivery_ports_missing');
  let closed=false,highWater=0;
  // Bounded negative fence for same-process concurrent/repeated admissions.
  // Durable exactly-once protection across restarts belongs to markDispatch.
  const operations=new Set<string>();
  const clock=()=>{
    need(!closed,'rich_delivery_closed');const t=time.call(ports);
    if(!integer(t)||t<highWater){closed=true;throw new RichDeliveryError('rich_delivery_clock');}
    highWater=t;return t;
  };
  return Object.freeze({
    close(){closed=true;},
    async deliver(attempt:unknown,signal:AbortSignal):Promise<DeliveryResult>{
      need(signal instanceof AbortSignal,'rich_delivery_signal');
      need(!signal.aborted,'rich_delivery_cancelled');clock();
      // An uncertain admission/reservation throws; never synthesize permission.
      const lease=await admit.call(ports,attempt,signal);
      need(lease&&typeof lease==='object');
      const operation=text(own(lease,'operation'),/^[A-Za-z0-9_-]+$/,160);
      need(!closed&&!signal.aborted,'rich_delivery_cancelled');
      if(operations.has(operation))return Object.freeze({outcome:'already_attempted'});
      need(operations.size<4096,'rich_delivery_capacity');operations.add(operation);
      // Snapshot primitive data before any further await; accessors are refused.
      const assertion=own(lease,'assertCurrent');need(typeof assertion==='function');
      const expiresAt=own(lease,'expiresAt');need(integer(expiresAt));
      const guard=()=>{
        need(!closed&&!signal.aborted,'rich_delivery_cancelled');
        const t=clock();need(t<expiresAt,'rich_delivery_expired');
        // Promise/boolean substitutes are not a synchronous owner check.
        need(assertion.call(lease)===undefined,'rich_delivery_owner');
        need(!closed&&!signal.aborted,'rich_delivery_cancelled');
        const after=clock();need(after<expiresAt,'rich_delivery_expired');return after;
      };
      let attempted=false,markerUncertain=false,observation:ProviderObservation={outcome:'not_sent'};
      try{
        guard();
        const carrier=own(lease,'carrier');const data=decodeRichCarrier(carrier);
        const original=own(lease,'original');need(original&&typeof original==='object');
        // Snapshot/validate all four original primitive fields; no caller getter
        // or JSON reserialization can rewrite the qualified original frame.
        const expected={attributes_utf8:own(original,'attributes_utf8'),content_state_utf8:own(original,'content_state_utf8'),
          source_observed_at_ms:own(original,'source_observed_at_ms'),source_expires_at_ms:own(original,'source_expires_at_ms')};
        checkOriginalRichData(data,expected as OriginalRichData);
        const event=own(lease,'event');need(event==='update'||event==='end');
        const dismissal=Object.getOwnPropertyDescriptor(lease,'dismissalAt');need(!dismissal||Object.hasOwn(dismissal,'value'));
        const token=text(own(lease,'token'),/^(?:[a-f0-9]{2}){16,2048}$/,4096);
        const topic=text(own(lease,'topic'),/^[A-Za-z0-9.-]+\.push-type\.liveactivity$/,255);
        const environment=own(lease,'environment');need(environment==='sandbox'||environment==='production');
        const t=guard();need(data.source_observed_at_ms<=t&&t<data.source_expires_at_ms,'rich_delivery_expired');
        need(expiresAt<=data.source_expires_at_ms,'rich_delivery_expired');
        const body=prepareApnsData(data,event,t,dismissal?.value);
        // Internal durable commitment binds target and exact body, not just the
        // rich frame. This is not the still-unselected public signature grammar.
        const bytes=new TextEncoder().encode(JSON.stringify([operation,environment,topic,token,expiresAt,body.body_utf8]));
        const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
        guard();
        const authorization=await authorize.call(ports);guard();
        need(typeof authorization==='string'&&authorization.length<=8192&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization),'rich_delivery_provider');
        markerUncertain=true;
        const marker=await mark.call(ports,operation,digest,expiresAt);
        if(marker==='already_attempted')return Object.freeze({outcome:'already_attempted'});
        need(marker==='marked','rich_delivery_marker');
        markerUncertain=false;
        const final=guard();
        const url=(environment==='sandbox'?'https://api.sandbox.push.apple.com':'https://api.push.apple.com')+'/3/device/'+token;
        const init:RequestInit={method:'POST',headers:{authorization:'bearer '+authorization,'apns-push-type':'liveactivity',
          'apns-topic':topic,'apns-expiration':String(Math.floor(expiresAt/1000)),'apns-priority':'5','content-type':'application/json'},
          body:body.body_utf8,redirect:'error',signal:AbortSignal.any([signal,AbortSignal.timeout(Math.max(1,Math.min(10000,expiresAt-final)))])};
        // Last synchronous owner check immediately before the sole outbound call.
        guard();attempted=true;
        const response=await fetcher.call(ports,url,init);
        observation=Object.freeze({outcome:response.status===200?'provider_accepted':'provider_rejected',status:response.status});
        // An APNs response is an observation, not device delivery or permission.
      }catch{
        observation=Object.freeze({outcome:attempted||markerUncertain?'outcome_unknown':'not_sent'});
      }
      try{await finish.call(ports,operation,observation);}catch{return Object.freeze({outcome:'outcome_unknown'});}
      try{guard();}catch{return Object.freeze({outcome:'outcome_unknown'});}
      return observation;
    },
  });
}
