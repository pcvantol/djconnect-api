import {test,expect,vi} from 'vitest';
import * as asn from 'asn1js';
import * as pki from 'pkijs';
import fixtures from 'djc-status-fixtures';
import {qualifyCommonStatus,qualifySyntheticStatus,CommonStatusCache} from './receipt-status-candidate.mjs';
const decode=v=>Uint8Array.from(atob(v),c=>c.charCodeAt(0)),root=decode(fixtures.root);
const clocks=async(at,body)=>{vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(at);try{await body();}finally{vi.useRealTimers();}};
for(const f of fixtures.genuine){
 const response=decode(f.response),cert=decode(f.cert),issuer=decode(f.issuer);
 const evaluate=()=>qualifyCommonStatus(f.kind,response,cert,issuer,root);
 test('actual common-certificate current eligibility: '+f.name,async()=>{
  const at=Date.now(),expected=at>=f.thisUpdate&&at<f.nextUpdate&&(f.kind==='crl'||at-f.thisUpdate<=86400000);
  expect(Boolean(await evaluate())).toBe(expected);
 });
 for(const [name,at]of [['before-thisUpdate',f.thisUpdate-1],['nextUpdate-equality',f.nextUpdate]]){
  test('signed status time denies '+name+': '+f.name,async()=>{await clocks(at,async()=>{expect(await evaluate()).toBeNull();});});
 }
 for(const name of ['signature','certificate','issuer','root','trailing','oversized']){
  test('signed status mutation denied '+name+': '+f.name,async()=>{
   let r=response.slice(),c=cert.slice(),i=issuer.slice(),a=root.slice();
   if(name==='signature'){if(f.kind==='ocsp'){const outer=new pki.OCSPResponse({schema:asn.fromBER(r).result}),basic=new pki.BasicOCSPResponse({schema:asn.fromBER(outer.responseBytes.response.valueBlock.valueHexView).result});basic.signature.valueBlock.valueHexView[10]^=1;outer.responseBytes.response=new asn.OctetString({valueHex:basic.toSchema().toBER(false)});r=new Uint8Array(outer.toSchema().toBER(false));}else{r[r.length-1]^=1;}}
   if(name==='certificate')c[10]^=1;if(name==='issuer')i[i.length-1]^=1;if(name==='root')a[a.length-1]^=1;
   if(name==='trailing')r=Uint8Array.from([...r,5,0]);if(name==='oversized')r=new Uint8Array(65537);
   expect(await qualifyCommonStatus(f.kind,r,c,i,a)).toBeNull();
  });
 }
 test('private cache binds exact tuple/no mutation renewal: '+f.name,async()=>{
  const cache=new CommonStatusCache(),at=f.referenceTime;
  await clocks(at,async()=>{
   expect(await cache.put(f.kind,response,cert,issuer,root)).toBe(true);const entry=await cache.get(f.kind,cert,issuer,root);expect(entry).not.toBeNull();const original=entry.cacheUntil;entry.cacheUntil+=999999;
   expect((await cache.get(f.kind,cert,issuer,root)).cacheUntil).toBe(original);
   const wrong=cert.slice();wrong[10]^=1;expect(await cache.get(f.kind,wrong,issuer,root)).toBeNull();
   // Same concatenated bytes with different tuple boundaries must NOT alias the cache key.
   const split=cert.length-1;expect(await cache.get(f.kind,cert.subarray(0,split),Uint8Array.from([...cert.subarray(split),...issuer]),root)).toBeNull();
   vi.setSystemTime(original);expect(await cache.get(f.kind,cert,issuer,root)).toBeNull();
  });
 });
 test('private cache denies clock rollback: '+f.name,async()=>{
  const cache=new CommonStatusCache(),at=f.referenceTime;
  await clocks(at,async()=>{expect(await cache.put(f.kind,response,cert,issuer,root)).toBe(true);vi.setSystemTime(at-1);expect(await cache.get(f.kind,cert,issuer,root)).toBeNull();});
 });
}
if(fixtures.genuine.length)test('status verification has no outbound fetch',async()=>{
 const spy=vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('network_forbidden'));
 try{for(const f of fixtures.genuine)await clocks(f.referenceTime,async()=>{expect(await qualifyCommonStatus(f.kind,decode(f.response),decode(f.cert),decode(f.issuer),root)).not.toBeNull();});expect(spy).not.toHaveBeenCalled();}finally{spy.mockRestore();}
});
test('empty cache cannot be seeded with a caller status object',async()=>{const cache=new CommonStatusCache();expect(await cache.get('ocsp',new Uint8Array([1]),new Uint8Array([2]),root)).toBeNull();});

for(const f of fixtures.synthetic){
 test('signed synthetic OCSP: '+f.name,async()=>{await clocks(f.now,async()=>{
  const input={...f};for(const key of ['response','cert','issuer','root'])input[key]=decode(f[key]);
  expect(Boolean(await qualifySyntheticStatus(input))).toBe(f.valid);
 });});
}
test('public wrapper refuses even valid synthetic root',async()=>{const f=fixtures.synthetic.find(v=>v.name==='valid-delegation');await clocks(f.now,async()=>{expect(await qualifyCommonStatus(f.kind,decode(f.response),decode(f.cert),decode(f.issuer),decode(f.root))).toBeNull();});});
