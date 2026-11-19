import {it,expect,vi,afterEach,beforeEach} from 'vitest';
import attributes from '../../rich-session/qualification/apple-fixtures/attributes_original_uuid.json?raw';
import state from '../../rich-session/qualification/apple-fixtures/state_rich_both.json?raw';
import {createRichDeliveryAdapter,type RichDeliveryPorts,type ReservedRichDelivery,type ProviderObservation} from '../adapter';
import {decodeRichCarrier} from '../../rich-session/profile-data';
const start=1800000000125,expiry=start+30000;
const b64=(s:string)=>btoa(String.fromCharCode(...new TextEncoder().encode(s))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
function setup(){
 let now=start,valid=true;const controller=new AbortController();const events:string[]=[],observations:ProviderObservation[]=[];
 const carrier=JSON.stringify({schema_version:1,profile_id:'djconnect-session-rich-v1',attributes_utf8_b64u:b64(attributes),content_state_utf8_b64u:b64(state),source_observed_at_ms:start,source_expires_at_ms:expiry});
 const data=decodeRichCarrier(carrier);
 const lease:ReservedRichDelivery={operation:'synthetic-original-operation',carrier,
  original:{attributes_utf8:attributes,content_state_utf8:state,source_observed_at_ms:start,source_expires_at_ms:expiry},
  event:'update',token:'ab'.repeat(32),topic:'test.example.push-type.liveactivity',environment:'sandbox',expiresAt:expiry,
  assertCurrent(){events.push('guard');if(!valid)throw Error('withdrawn');}};
 const ports:RichDeliveryPorts={now:()=>now,
  admitAndReserve:vi.fn(async()=>{events.push('reserve');return lease;}),
  authorizeProvider:vi.fn(async()=>{events.push('authorize');return 'synthetic.provider.signature';}),
  markDispatch:vi.fn(async()=>{events.push('marker');return 'marked' as const;}),
  finish:vi.fn(async(_op,o)=>{events.push('finish');observations.push(o);}),
  fetcher:vi.fn(async()=>{events.push('fetch');return new Response(null,{status:200});}) as unknown as typeof fetch};
 return {ports,lease,data,controller,events,observations,setTime:(n:number)=>{now=n;},withdraw:()=>{valid=false;},run:()=>createRichDeliveryAdapter(ports).deliver('opaque-synthetic-attempt',controller.signal)};
}
let network:ReturnType<typeof vi.spyOn>,generate:ReturnType<typeof vi.spyOn>,sign:ReturnType<typeof vi.spyOn>;
beforeEach(()=>{network=vi.spyOn(globalThis,'fetch').mockImplementation(()=>{throw Error('actual network forbidden');});generate=vi.spyOn(crypto.subtle,'generateKey').mockImplementation(()=>{throw Error('actual key generation forbidden');});sign=vi.spyOn(crypto.subtle,'sign').mockImplementation(()=>{throw Error('actual signing forbidden');});});
afterEach(()=>{expect(network).not.toHaveBeenCalled();expect(generate).not.toHaveBeenCalled();expect(sign).not.toHaveBeenCalled();vi.restoreAllMocks();});
it('has no default admission/provider/ledger/network ports',()=>{for(const x of [undefined,null,{}, {admitAndReserve:()=>{}}])expect(()=>createRichDeliveryAdapter(x as unknown as RichDeliveryPorts)).toThrow();});
it('sends exact original raw ContentState, after reservation/auth/durable marker and final guard',async()=>{
 const s=setup();expect(await s.run()).toEqual({outcome:'provider_accepted',status:200});
 const call=vi.mocked(s.ports.fetcher).mock.calls[0];expect(call[0]).toBe('https://api.sandbox.push.apple.com/3/device/'+'ab'.repeat(32));
 const init=call[1]!;expect(init.body).toContain('"content-state":'+state);expect(new TextEncoder().encode(init.body as string).length).toBeLessThanOrEqual(4096);
 expect(init.redirect).toBe('error');expect(s.events.indexOf('reserve')).toBeLessThan(s.events.indexOf('authorize'));expect(s.events.indexOf('authorize')).toBeLessThan(s.events.indexOf('marker'));expect(s.events[s.events.indexOf('fetch')-1]).toBe('guard');
 expect(s.observations).toEqual([{outcome:'provider_accepted',status:200}]);expect(s.ports.markDispatch).toHaveBeenCalledWith(s.lease.operation,expect.stringMatching(/^[a-f0-9]{64}$/),expiry);
});
for(const point of ['admission','authorization','marker'] as const)for(const change of ['withdraw','abort','expiry','rollback'] as const)it(change+' during '+point+' prevents outbound request',async()=>{
 const s=setup();
 const mutate=()=>{if(change==='withdraw')s.withdraw();if(change==='abort')s.controller.abort();if(change==='expiry')s.setTime(expiry);if(change==='rollback')s.setTime(start-1);};
 if(point==='admission')s.ports.admitAndReserve=async()=>{mutate();return s.lease;};
 // Ports are captured at construction, so construct after injecting the await.
 if(point==='authorization')s.ports.authorizeProvider=async()=>{mutate();return 'synthetic.provider.signature';};
 if(point==='marker')s.ports.markDispatch=async()=>{mutate();return 'marked';};
 const target=createRichDeliveryAdapter(s.ports);
 await target.deliver('opaque',s.controller.signal).catch(()=>undefined);expect(s.ports.fetcher).not.toHaveBeenCalled();
});
it('close while provider authorization is pending prevents dispatch',async()=>{const s=setup();let release!:()=>void;s.ports.authorizeProvider=async()=>{await new Promise<void>(r=>{release=r;});return 'synthetic.provider.signature';};const a=createRichDeliveryAdapter(s.ports);const p=a.deliver('opaque',s.controller.signal);while(!release)await Promise.resolve();a.close();release();expect((await p).outcome).toBe('outcome_unknown');expect(s.ports.fetcher).not.toHaveBeenCalled();});
for(const mutation of ['carrier','original','token','topic','environment','event','expiry','asyncguard'] as const)it('rejects invalid '+mutation+' without fetching',async()=>{
 const s=setup();const l=s.lease as unknown as Record<string,unknown>;
 if(mutation==='carrier')l.carrier=s.lease.carrier.replace('1800000030125','1800000030126');if(mutation==='original')l.original={...s.lease.original,content_state_utf8:state+' '};
 if(mutation==='token')l.token='not-a-token';if(mutation==='topic')l.topic='test\r\ninjected';if(mutation==='environment')l.environment='https://attacker.invalid';if(mutation==='event')l.event='start';if(mutation==='expiry')l.expiresAt=expiry+1;if(mutation==='asyncguard')l.assertCurrent=async()=>{};
 expect((await s.run()).outcome).toBe(mutation==='asyncguard'?'outcome_unknown':'not_sent');expect(s.ports.fetcher).not.toHaveBeenCalled();
});
it('refuses a copied malformed or accessor original without executing its getter',async()=>{const s=setup();const getter=vi.fn(()=>state);Object.defineProperty(s.lease.original,'content_state_utf8',{get:getter});expect((await s.run()).outcome).toBe('not_sent');expect(getter).not.toHaveBeenCalled();expect(s.ports.fetcher).not.toHaveBeenCalled();});
it('concurrent duplicate admission produces at most one outbound attempt',async()=>{const s=setup();const a=createRichDeliveryAdapter(s.ports);const r=await Promise.all([a.deliver('x',s.controller.signal),a.deliver('x',s.controller.signal)]);expect(r.map(x=>x.outcome).sort()).toEqual(['already_attempted','provider_accepted']);expect(s.ports.fetcher).toHaveBeenCalledTimes(1);});
it('durable duplicate after process replacement does not fetch or finish old operation',async()=>{const s=setup();s.ports.markDispatch=vi.fn(async()=> 'already_attempted' as const);expect(await s.run()).toEqual({outcome:'already_attempted'});expect(s.ports.fetcher).not.toHaveBeenCalled();expect(s.ports.finish).not.toHaveBeenCalled();});
it('lost durable marker ACK is UNKNOWN and never permits outbound retry',async()=>{const s=setup();s.ports.markDispatch=vi.fn(async()=>{throw Error('lost ACK');});const a=createRichDeliveryAdapter(s.ports);expect((await a.deliver('x',s.controller.signal)).outcome).toBe('outcome_unknown');expect((await a.deliver('x',s.controller.signal)).outcome).toBe('already_attempted');expect(s.ports.fetcher).not.toHaveBeenCalled();});
it('lost provider ACK is UNKNOWN with exactly one attempt and no automatic retry',async()=>{const s=setup();s.ports.fetcher=vi.fn(async()=>{throw Error('lost ACK');}) as unknown as typeof fetch;const a=createRichDeliveryAdapter(s.ports);expect((await a.deliver('x',s.controller.signal)).outcome).toBe('outcome_unknown');await a.deliver('x',s.controller.signal);expect(s.ports.fetcher).toHaveBeenCalledTimes(1);});
it('accepted provider followed by lost finish ACK stays UNKNOWN, never replayed',async()=>{const s=setup();s.ports.finish=vi.fn(async()=>{throw Error('lost finish ACK');});expect((await s.run()).outcome).toBe('outcome_unknown');expect(s.ports.fetcher).toHaveBeenCalledTimes(1);});
it('withdrawal while provider response is pending preserves observation but returns no positive authority',async()=>{const s=setup();s.ports.fetcher=vi.fn(async()=>{s.withdraw();return new Response(null,{status:200});}) as unknown as typeof fetch;expect((await s.run()).outcome).toBe('outcome_unknown');expect(s.observations).toEqual([{outcome:'provider_accepted',status:200}]);});
it('provider rejection remains rejection rather than device success',async()=>{const s=setup();s.ports.fetcher=vi.fn(async()=>new Response(null,{status:410})) as unknown as typeof fetch;expect(await s.run()).toEqual({outcome:'provider_rejected',status:410});});
it('internal commitment changes when target token changes, raw body remaining exact',async()=>{const a=setup(),b=setup();(b.lease as {token:string}).token='cd'.repeat(32);await a.run();await b.run();expect(vi.mocked(a.ports.markDispatch).mock.calls[0][1]).not.toBe(vi.mocked(b.ports.markDispatch).mock.calls[0][1]);});
it('failed original admission does not reach provider authorization, ledger or network',async()=>{const s=setup();s.ports.admitAndReserve=vi.fn(async()=>{throw Error('unavailable real custody');});await expect(s.run()).rejects.toThrow();expect(s.ports.authorizeProvider).not.toHaveBeenCalled();expect(s.ports.markDispatch).not.toHaveBeenCalled();expect(s.ports.fetcher).not.toHaveBeenCalled();});
it('provider authorization failure is not sent and cannot retry same original operation',async()=>{const s=setup();s.ports.authorizeProvider=vi.fn(async()=>{throw Error('unavailable provider');});const a=createRichDeliveryAdapter(s.ports);expect((await a.deliver('x',s.controller.signal)).outcome).toBe('not_sent');expect((await a.deliver('x',s.controller.signal)).outcome).toBe('already_attempted');expect(s.ports.fetcher).not.toHaveBeenCalled();});
it('malformed durable marker response is uncertain and prevents outbound',async()=>{const s=setup();s.ports.markDispatch=vi.fn(async()=>undefined as unknown as 'marked');expect((await s.run()).outcome).toBe('outcome_unknown');expect(s.ports.fetcher).not.toHaveBeenCalled();});
it('mutating supplied lease primitive after await cannot substitute the captured target',async()=>{const s=setup();s.ports.authorizeProvider=async()=>{(s.lease as {token:string}).token='cd'.repeat(32);return 'synthetic.provider.signature';};await s.run();expect(vi.mocked(s.ports.fetcher).mock.calls[0][0]).toBe('https://api.sandbox.push.apple.com/3/device/'+'ab'.repeat(32));});
it('withdrawal during finish preserves actual provider observation and returns UNKNOWN',async()=>{const s=setup();s.ports.finish=async(_op,o)=>{s.observations.push(o);s.withdraw();};expect((await s.run()).outcome).toBe('outcome_unknown');expect(s.observations).toEqual([{outcome:'provider_accepted',status:200}]);});
it('raw original integer aliases are rejected before provider authorization',async()=>{const s=setup();(s.lease as {carrier:string}).carrier=s.lease.carrier.replace('1800000030125','1800000030125.00000000000001');expect((await s.run()).outcome).toBe('not_sent');expect(s.ports.authorizeProvider).not.toHaveBeenCalled();expect(s.ports.fetcher).not.toHaveBeenCalled();});
it('already aborted request is refused before any original admission',async()=>{const s=setup();s.controller.abort();await expect(s.run()).rejects.toThrow();expect(s.ports.admitAndReserve).not.toHaveBeenCalled();});
it('end event retains exact original content and explicit dismissal',async()=>{const s=setup();Object.assign(s.lease,{event:'end',dismissalAt:start-1000});expect((await s.run()).outcome).toBe('provider_accepted');const body=vi.mocked(s.ports.fetcher).mock.calls[0][1]!.body as string;expect(body).toContain('"event":"end"');expect(body).toContain('"dismissal-date":'+Math.floor((start-1000)/1000));expect(body).toContain('"content-state":'+state);});
it('oversized actual final APS fails before provider authorization',async()=>{const s=setup();const d=decodeRichCarrier(s.lease.carrier);const bodyLength=new TextEncoder().encode('{"aps":{"timestamp":1800000000,"event":"update","content-state":'+state+',"stale-date":1800000030}}').length;const padded=state+' '.repeat(4097-bodyLength);Object.assign(s.lease,{carrier:JSON.stringify({schema_version:1,profile_id:'djconnect-session-rich-v1',attributes_utf8_b64u:b64(attributes),content_state_utf8_b64u:b64(padded),source_observed_at_ms:start,source_expires_at_ms:expiry}),original:{...s.lease.original,content_state_utf8:padded}});expect(d.rich_shape).toBe(true);expect((await s.run()).outcome).toBe('not_sent');expect(s.ports.authorizeProvider).not.toHaveBeenCalled();expect(s.ports.fetcher).not.toHaveBeenCalled();});
for(const field of ['operation','token','topic','authorization'] as const)it('requires the entire '+field+' string, including refusal of a final LF',async()=>{const s=setup();if(field==='authorization')s.ports.authorizeProvider=async()=> 'synthetic.provider.signature\n';else (s.lease as unknown as Record<string,string>)[field]+='\n';await s.run().catch(()=>undefined);expect(s.ports.fetcher).not.toHaveBeenCalled();});
