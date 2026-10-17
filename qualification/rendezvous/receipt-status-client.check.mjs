import {test,expect,vi} from 'vitest';
import * as asn from 'asn1js';
import * as pki from 'pkijs';
import fixtures from 'djc-status-fixtures';
import {CommonStatusClient} from './receipt-status-client.mjs';
import {prepareCommonStatusRequest} from './receipt-status-candidate.mjs';
const decode=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0)),root=decode(fixtures.root);
const at=async(f,body)=>{vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(f.referenceTime);try{await body();}finally{vi.useRealTimers();}};
const check=(client,f)=>client.check(f.kind,decode(f.cert),decode(f.issuer),root);
const good=f=>new Response(decode(f.response),{headers:{'content-type':f.kind==='ocsp'?'application/ocsp-response':'application/pkix-crl'}});
for(const f of fixtures.genuine){
 test('fixed authenticated egress and cache: '+f.name,async()=>{await at(f,async()=>{
  const fetcher=vi.fn(async(url,options)=>{
   expect(url).toBe(f.kind==='crl'?'http://crl.apple.com/applerootcag3.crl':'http://ocsp.apple.com/'+(f.name==='signer'?'ocsp03-aaica5g101':'ocsp03-applerootcag3'));
   expect(options).toMatchObject({redirect:'manual',credentials:'omit',referrerPolicy:'no-referrer',cache:'no-store'});
   expect(options.headers.authorization).toBeUndefined();
   if(f.kind==='ocsp'){
    expect(options.method).toBe('POST');const request=new pki.OCSPRequest({schema:asn.fromBER(options.body).result});
    expect(request.tbsRequest.requestList).toHaveLength(1);expect(request.optionalSignature).toBeUndefined();expect(request.tbsRequest.requestExtensions).toBeUndefined();
    const outer=new pki.OCSPResponse({schema:asn.fromBER(decode(f.response)).result}),response=new pki.BasicOCSPResponse({schema:asn.fromBER(outer.responseBytes.response.valueBlock.valueHexView).result});
    expect(request.tbsRequest.requestList[0].reqCert.isEqual(response.tbsResponseData.responses[0].certID)).toBe(true);
   }else{expect(options.method).toBe('GET');expect(options.body).toBeUndefined();}
   return good(f);
  });
  const client=new CommonStatusClient(fetcher),first=await check(client,f);expect(first.ok).toBe(true);expect(first.source).toBe('network');
  fetcher.mockRejectedValue(new Error('private_detail_should_not_escape'));const again=await check(client,f);expect(again.ok).toBe(true);expect(again.source).toBe('cache');expect(again.cacheUntil).toBe(first.cacheUntil);expect(fetcher).toHaveBeenCalledTimes(1);
  vi.setSystemTime(first.cacheUntil);fetcher.mockRejectedValue(new Error('private_detail_should_not_escape'));expect(await check(client,f)).toEqual({ok:false,error:'status_unavailable'});expect(fetcher).toHaveBeenCalledTimes(2);
 });});
 test('same-context concurrent status checks coalesce: '+f.name,async()=>{await at(f,async()=>{const fetcher=vi.fn(async()=>good(f)),client=new CommonStatusClient(fetcher);const results=await Promise.all(Array.from({length:8},()=>check(client,f)));expect(results.every(v=>v.ok)).toBe(true);expect(fetcher).toHaveBeenCalledTimes(1);});});
 for(const failure of ['outage','redirect','wrong-type','empty','declared-large','stream-large','bad-signature']){
  test('status egress denies '+failure+': '+f.name,async()=>{await at(f,async()=>{
   const fetcher=vi.fn(async()=>{
    if(failure==='outage')throw new Error('private_status_detail');
    if(failure==='redirect')return new Response(null,{status:302,headers:{location:'https://unsafe.example'}});
    if(failure==='wrong-type')return new Response(decode(f.response),{headers:{'content-type':'text/html'}});
    const headers={'content-type':f.kind==='ocsp'?'application/ocsp-response':'application/pkix-crl'};
    if(failure==='empty')return new Response(null,{headers});
    if(failure==='declared-large')return new Response(decode(f.response),{headers:{...headers,'content-length':'65537'}});
    if(failure==='stream-large')return new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array(32768));c.enqueue(new Uint8Array(32768));c.enqueue(new Uint8Array(1));c.close();}}),{headers});
    const bytes=decode(f.response);bytes[bytes.length-1]^=1;return new Response(bytes,{headers});
   });
   const client=new CommonStatusClient(fetcher);expect(await check(client,f)).toEqual({ok:false,error:'status_unavailable'});
   fetcher.mockImplementation(async()=>good(f));expect(await check(client,f)).toEqual({ok:false,error:'status_unavailable'});expect(fetcher).toHaveBeenCalledTimes(1);
   vi.setSystemTime(f.referenceTime+2000);expect((await check(client,f)).source).toBe('network');expect(fetcher).toHaveBeenCalledTimes(2);
  });});
 }
}
for(const name of ['headers-timeout','body-timeout']){
 if(fixtures.genuine.length)test('absolute network deadline '+name,async()=>{const f=fixtures.genuine[0];await at(f,async()=>{
  let cancelled=false;const fetcher=vi.fn(async()=>name==='headers-timeout'?new Promise(()=>{}):new Response(new ReadableStream({cancel(){cancelled=true;}}),{headers:{'content-type':'application/ocsp-response'}}));
  const before=performance.now();expect(await check(new CommonStatusClient(fetcher),f)).toEqual({ok:false,error:'status_unavailable'});expect(performance.now()-before).toBeLessThan(6000);expect(fetcher.mock.calls[0][1].signal.aborted).toBe(true);if(name==='body-timeout')expect(cancelled).toBe(true);
 });});
}
test('untrusted certificate profile never emits a status request',async()=>{
 const f=fixtures.synthetic.find(v=>v.name==='valid-delegation'),fetcher=vi.fn(async()=>{throw new Error('must_not_fetch');}),client=new CommonStatusClient(fetcher);
 expect(await client.check(f.kind,decode(f.cert),decode(f.issuer),decode(f.root))).toEqual({ok:false,error:'status_unavailable'});expect(fetcher).not.toHaveBeenCalled();
});
// Orchestration fault injection substitutes ONLY the prerequisite context preparer.
// B is not a real second Apple certificate; no cryptographic acceptance of B is claimed.
if(fixtures.genuine.length){
 const f=fixtures.genuine[0],cert=decode(f.cert),issuer=decode(f.issuer),other=cert.slice();other[10]^=1;
 const defer=()=>{let resolve;const promise=new Promise(r=>{resolve=r;});return {promise,resolve};};
 const setup=async()=>{const request=await prepareCommonStatusRequest(f.kind,cert,issuer,root);return async()=>({...request,body:request.body?.slice()});};
 test('A/B/A tuple switches cannot multiply active role operations',async()=>{await at(f,async()=>{
  const entered=defer(),gate=defer(),fetcher=vi.fn(async()=>{entered.resolve();return gate.promise;}),client=new CommonStatusClient(fetcher,await setup());
  const first=check(client,f);await entered.promise;vi.setSystemTime(f.referenceTime+3000);
  expect(await client.check(f.kind,other,issuer,root)).toEqual({ok:false,error:'status_unavailable'});
  const again=check(client,f);gate.resolve(good(f));expect((await first).ok).toBe(true);expect((await again).ok).toBe(true);expect(fetcher).toHaveBeenCalledTimes(1);
 });});
 test('failed replacement preserves previous verified tuple cache',async()=>{await at(f,async()=>{
  const fetcher=vi.fn(async()=>good(f)),client=new CommonStatusClient(fetcher,await setup());expect((await check(client,f)).ok).toBe(true);vi.setSystemTime(f.referenceTime+2000);
  expect(await client.check(f.kind,other,issuer,root)).toEqual({ok:false,error:'status_unavailable'});
  expect((await check(client,f)).source).toBe('cache');expect(fetcher).toHaveBeenCalledTimes(2);
 });});
 test('late timed-out operation cannot release or promote newer operation',async()=>{await at(f,async()=>{
  const oldEntered=defer(),oldGate=defer(),newEntered=defer(),newGate=defer();
  const fetcher=vi.fn().mockImplementationOnce(async()=>{oldEntered.resolve();return oldGate.promise;}).mockImplementationOnce(async()=>{newEntered.resolve();return newGate.promise;});
  const client=new CommonStatusClient(fetcher,await setup()),old=check(client,f);await oldEntered.promise;expect(await old).toEqual({ok:false,error:'status_unavailable'});
  vi.setSystemTime(f.referenceTime+5000);const current=check(client,f);await newEntered.promise;oldGate.resolve(good(f));
  await new Promise(resolve=>setTimeout(resolve,20));expect(await client.check(f.kind,other,issuer,root)).toEqual({ok:false,error:'status_unavailable'});
  const same=check(client,f);newGate.resolve(good(f));expect((await current).ok).toBe(true);expect((await same).ok).toBe(true);expect(fetcher).toHaveBeenCalledTimes(2);expect((await check(client,f)).source).toBe('cache');
 });});
}
