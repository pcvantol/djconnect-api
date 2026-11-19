import {it,expect,beforeAll,beforeEach,afterEach,vi} from 'vitest';
import {env} from 'cloudflare:workers';
import {SELF,runInDurableObject} from 'cloudflare:test';
import type {PrincipalRegistryData} from '../registry';
import {SOURCE,canonical,type RegistryData} from '../model';
import worker,{createProductionRegistry} from '../worker';
import {sha256Hex} from '../../../src/crypto';
declare global { namespace Cloudflare { interface Env {REGISTRY_DATA:DurableObjectNamespace<PrincipalRegistryData>} } }
declare module 'cloudflare:test' {interface ProvidedEnv {REGISTRY_DATA:DurableObjectNamespace<PrincipalRegistryData>}}
const H=(n:number)=>n.toString(16).padStart(64,'0');
const U=(n:number)=>`00000000-0000-4000-8000-${n.toString(16).padStart(12,'0')}`;
const coord=(hex:string)=>btoa(String.fromCharCode(...hex.match(/../g)!.map(v=>parseInt(v,16)))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
// Public P-256 base point only; no private key, registrar identity or live PoP.
const jwk={kty:'EC',crv:'P-256',x:coord('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  y:coord('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')};
let record:RegistryData;
beforeAll(async()=>{const bytes=canonical(jwk);record={principal_id:'source-core-principal',principal_epoch:1,
  core_instance_id:'source-core-instance',installation_id:'source-ha-install',accepted_pair_binding_sha256:H(2),
  public_key_jwk_canonical:bytes,public_key_thumbprint:await sha256Hex(bytes),allowed_purposes:['paired-device-transport'],
  policy_sha256:H(3),registration_provenance_sha256:H(4),pop_receipt_sha256:H(5),original_permission_expires_at_unix_ms:1000};});
type Stub=DurableObjectStub<PrincipalRegistryData>;
async function call(s:Stub,action:string,input:unknown) {return JSON.parse(await s.sourceCommand(JSON.stringify({classification:SOURCE,action,input})));}
async function setup(max_records=4,max_operations=20) {
  const s=env.REGISTRY_DATA.get(env.REGISTRY_DATA.newUniqueId());
  expect((await call(s,'initialize',{restore:H(1),max_records,max_operations})).ok).toBe(true);return s;
}
const registration=(r=record,revision=0,n=1)=>({restore:H(1),expected_revision:revision,operation_id:U(n),nonce_sha256:H(100+n),record:r});
const retirement=(r=record,revision=1,n=2)=>({restore:H(1),expected_revision:revision,operation_id:U(n),nonce_sha256:H(100+n),principal_id:r.principal_id,principal_epoch:r.principal_epoch});
const lookup=(r=record)=>({restore:H(1),principal_id:r.principal_id,principal_epoch:r.principal_epoch,core_instance_id:r.core_instance_id,
  installation_id:r.installation_id,accepted_pair_binding_sha256:r.accepted_pair_binding_sha256,purpose:'paired-device-transport'});
async function rows(s:Stub,table:string) {return runInDurableObject(s,(_i,state)=>state.storage.sql.exec(`SELECT * FROM ${table}`).toArray());}
let egress:ReturnType<typeof vi.fn>;
beforeEach(()=>{egress=vi.fn(()=>{throw Error('source egress forbidden');});vi.stubGlobal('fetch',egress);});
afterEach(()=>{expect(egress).not.toHaveBeenCalled();vi.unstubAllGlobals();});

it('production factory fails before argument/env/namespace access; HTTP stays no-store 503',async()=>{
  const trap=new Proxy({}, {get(){throw Error('argument touched');}});expect(()=>createProductionRegistry(trap)).toThrow('registrar authority');
  expect(worker.fetch()).toMatchObject({status:503});const response=await SELF.fetch('https://source.invalid/register',{method:'POST',body:'untrusted'});
  expect(response.status).toBe(503);expect(response.headers.get('Cache-Control')).toBe('no-store');
});
it('actual SQLite DO stores only source public DATA, with correct canonical pin and global revision',async()=>{
  const s=await setup(),reply=await call(s,'register',registration());expect(reply).toMatchObject({classification:SOURCE,ok:true,result:{revision:1,state:'STORED_SOURCE_DATA'}});
  const read=await call(s,'read',lookup());expect(read).toMatchObject({classification:SOURCE,ok:true,result:{revision:1,record}});
  expect(read.result.state).not.toBe('ACTIVE');expect(await rows(s,'registry_records')).toHaveLength(1);
  expect((await rows(s,'registry_records'))[0].body).not.toContain('private');
});
it('initialize is once-only and restores are checked before mutation/read',async()=>{
  const s=await setup();expect((await call(s,'initialize',{restore:H(1),max_records:4,max_operations:20})).ok).toBe(false);
  expect((await call(s,'register',{...registration(),restore:H(2)})).ok).toBe(false);
  expect(await rows(s,'registry_operations')).toHaveLength(0);
  await call(s,'register',registration());expect((await call(s,'read',{...lookup(),restore:H(2)})).ok).toBe(false);
});
it.each(['core_instance_id','installation_id','accepted_pair_binding_sha256','purpose'] as const)('read cannot substitute %s',async field=>{
  const s=await setup();await call(s,'register',registration());
  const input={...lookup(),[field]:field==='accepted_pair_binding_sha256'?H(8):field==='purpose'?'paired-session-status-child':'other'};
  expect((await call(s,'read',input)).ok).toBe(false);
});
it.each(['pin','private','offcurve','noncanonical','coordinate','purpose','extra','missing'] as const)('invalid %s record never consumes operation/nonce/revision',async kind=>{
  const s=await setup();const r:Record<string,unknown>={...record};
  if(kind==='pin')r.public_key_thumbprint=H(9);
  if(kind==='private')r.public_key_jwk_canonical=canonical({...jwk,d:'not-accepted'});
  if(kind==='offcurve')r.public_key_jwk_canonical=canonical({...jwk,x:'A'.repeat(43),y:'A'.repeat(43)});
  if(kind==='noncanonical')r.public_key_jwk_canonical=JSON.stringify(jwk);
  if(kind==='coordinate')r.public_key_jwk_canonical=canonical({...jwk,x:jwk.x+'='});
  if(kind==='purpose')r.allowed_purposes=['global-admin'];if(kind==='extra')r.admin=true;if(kind==='missing')delete r.pop_receipt_sha256;
  if(typeof r.public_key_jwk_canonical==='string' && kind!=='pin')r.public_key_thumbprint=await sha256Hex(r.public_key_jwk_canonical);
  expect((await call(s,'register',registration(r as unknown as RegistryData))).ok).toBe(false);
  expect(await rows(s,'registry_records')).toHaveLength(0);expect(await rows(s,'registry_operations')).toHaveLength(0);
  expect((await rows(s,'registry_meta'))[0].revision).toBe(0);
});
it('one concurrent global-revision winner; the losing operation and record both roll back',async()=>{
  const s=await setup();const results=await Promise.all([call(s,'register',registration()),call(s,'register',registration({...record,principal_id:'other'},0,2))]);
  expect(results.filter(x=>x.ok)).toHaveLength(1);expect(await rows(s,'registry_records')).toHaveLength(1);expect(await rows(s,'registry_operations')).toHaveLength(1);
});
it('key and record are immutable within an epoch and rotation requires previous retirement',async()=>{
  const s=await setup();expect((await call(s,'register',registration())).ok).toBe(true);
  expect((await call(s,'register',registration({...record,policy_sha256:H(9)},1,2))).ok).toBe(false);
  expect((await call(s,'register',registration({...record,principal_epoch:2},1,2))).ok).toBe(false);
  expect((await call(s,'retire',retirement())).ok).toBe(true);
  expect((await call(s,'read',lookup())).ok).toBe(false);
  expect((await call(s,'register',registration({...record,principal_epoch:2},2,3))).ok).toBe(true);
  expect((await call(s,'read',lookup({...record,principal_epoch:2}))).ok).toBe(true);
  expect(await rows(s,'registry_retired')).toHaveLength(1);
});
it('a different valid public curve point cannot replace the key inside an existing epoch',async()=>{
  const s=await setup();await call(s,'register',registration());
  const prime=BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
  const y=BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');
  const bytes=canonical({...jwk,y:coord((prime-y).toString(16).padStart(64,'0'))});
  const alternate={...record,public_key_jwk_canonical:bytes,public_key_thumbprint:await sha256Hex(bytes)};
  expect((await call(s,'register',registration(alternate,1,2))).ok).toBe(false);
  await call(s,'retire',retirement());
  expect((await call(s,'register',registration({...alternate,principal_epoch:2},2,3))).ok).toBe(true);
  expect((await call(s,'read',lookup({...alternate,principal_epoch:2}))).result.record.public_key_thumbprint).toBe(alternate.public_key_thumbprint);
});
it('one immutable registered public key can carry both existing receipt purposes as DATA',async()=>{
  const s=await setup();const r:RegistryData={...record,allowed_purposes:['paired-device-transport','paired-session-status-child']};
  expect((await call(s,'register',registration(r))).ok).toBe(true);
  expect((await call(s,'read',lookup(r))).ok).toBe(true);
  expect((await call(s,'read',{...lookup(r),purpose:'paired-session-status-child'})).ok).toBe(true);
});
it.each([{purposes:[]},{purposes:['paired-device-transport','paired-device-transport']},{purposes:['paired-session-status-child','paired-device-transport']}])('invalid or ambiguous purpose list rejects: $purposes',async({purposes})=>{
  const s=await setup();expect((await call(s,'register',registration({...record,allowed_purposes:purposes as RegistryData['allowed_purposes']}))).ok).toBe(false);
  expect(await rows(s,'registry_operations')).toHaveLength(0);
});
it('retirement before registration creates a durable tombstone; no ABA or skipped epoch',async()=>{
  const s=await setup();expect((await call(s,'retire',retirement(record,0,1))).ok).toBe(true);
  expect((await call(s,'register',registration(record,1,2))).ok).toBe(false);
  expect((await call(s,'register',registration({...record,principal_epoch:3},1,2))).ok).toBe(false);
  expect((await call(s,'register',registration({...record,principal_epoch:2},1,2))).ok).toBe(true);
});
it.each(['operation_id','nonce_sha256'] as const)('global %s replay across principals/actions rolls back the whole transaction',async field=>{
  const s=await setup();await call(s,'register',registration());
  const r=retirement({...record,principal_id:'other'},1,2);const old=registration();r[field]=old[field];
  expect((await call(s,'retire',r)).ok).toBe(false);expect(await rows(s,'registry_retired')).toHaveLength(0);
  expect((await rows(s,'registry_meta'))[0].revision).toBe(1);expect(await rows(s,'registry_operations')).toHaveLength(1);
});
it('real SQL fault after reservation/meta change rolls back operation, record, head and revision',async()=>{
  const s=await setup();await runInDurableObject(s,(_i,state)=>{
    state.storage.sql.exec("CREATE TRIGGER qualification_abort BEFORE INSERT ON registry_records BEGIN SELECT RAISE(ABORT,'qualification SQL fault'); END").toArray();
  });
  expect((await call(s,'register',registration())).ok).toBe(false);expect(await rows(s,'registry_operations')).toHaveLength(0);
  expect(await rows(s,'registry_heads')).toHaveLength(0);expect((await rows(s,'registry_meta'))[0].revision).toBe(0);
});
it('lost reply after real commit is not rollback; same operation or same epoch cannot be repaired/reissued',async()=>{
  const s=await setup();await s.sourceCommand(JSON.stringify({classification:SOURCE,action:'register',input:registration()})); // Deliberately discard actual reply.
  expect(await rows(s,'registry_records')).toHaveLength(1);
  expect((await call(s,'register',registration())).ok).toBe(false);
  expect((await call(s,'register',registration(record,1,2))).ok).toBe(false);
  expect(await rows(s,'registry_operations')).toHaveLength(1);
});
it('a failure after actual persistence returns negative DATA while preserving committed once/record state',async()=>{
  const s=await setup();const wire=JSON.stringify({classification:SOURCE,action:'register',input:registration()});
  await runInDurableObject(s,async(instance,state)=>{
    const original=state.storage.sync.bind(state.storage);
    const spy=vi.spyOn(state.storage,'sync').mockImplementation(async()=>{await original();throw Error('post-persistence fault');});
    try{expect(JSON.parse(await instance.sourceCommand(wire)).ok).toBe(false);}finally{spy.mockRestore();}
  });
  expect(await rows(s,'registry_records')).toHaveLength(1);expect(await rows(s,'registry_operations')).toHaveLength(1);
  expect((await rows(s,'registry_meta'))[0].revision).toBe(1);
  expect((await call(s,'register',registration())).ok).toBe(false);
});
it('finite record and operation budgets do not prune replay/retirement state',async()=>{
  const s=await setup(1,2);await call(s,'register',registration());
  expect((await call(s,'register',registration({...record,principal_id:'other'},1,2))).ok).toBe(false);
  expect((await call(s,'retire',retirement())).ok).toBe(true);
  expect((await call(s,'retire',retirement({...record,principal_id:'other'},2,3))).ok).toBe(false);
  expect(await rows(s,'registry_operations')).toHaveLength(2);expect(await rows(s,'registry_retired')).toHaveLength(1);
});
it('retirement capacity: registration needs room for its own later retirement',async()=>{
  const s=await setup(1,1);
  expect((await call(s,'register',registration())).ok).toBe(false);
  expect(await rows(s,'registry_records')).toHaveLength(0);
  expect(await rows(s,'registry_operations')).toHaveLength(0);
  expect((await rows(s,'registry_meta'))[0].revision).toBe(0);
  // Refusal does not consume the operation/nonce: a negative tombstone still fits.
  expect((await call(s,'retire',retirement(record,0,1))).ok).toBe(true);
});
it('retirement capacity: full admission still permits every stored live epoch to retire through a new stub',async()=>{
  const s=await setup(4,4),other={...record,principal_id:'other'};
  expect((await call(s,'register',registration())).ok).toBe(true);
  expect((await call(s,'register',registration(other,1,2))).ok).toBe(true);
  const again=env.REGISTRY_DATA.get(s.id);
  expect((await call(again,'register',registration({...record,principal_id:'third'},2,3))).ok).toBe(false);
  expect((await call(again,'retire',retirement({...record,principal_id:'unknown'},2,3))).ok).toBe(false);
  expect(await rows(again,'registry_operations')).toHaveLength(2);
  expect((await call(again,'retire',retirement(record,2,3))).ok).toBe(true);
  expect((await call(again,'retire',retirement(other,3,4))).ok).toBe(true);
  expect((await call(again,'read',lookup())).ok).toBe(false);
  expect((await call(again,'read',lookup(other))).ok).toBe(false);
  expect(await rows(again,'registry_operations')).toHaveLength(4);
  expect(await rows(again,'registry_retired')).toHaveLength(2);
});
it('retirement capacity: an unknown tombstone cannot spend another principal retirement slot',async()=>{
  const s=await setup(3,3);
  expect((await call(s,'register',registration())).ok).toBe(true);
  expect((await call(s,'retire',retirement({...record,principal_id:'unknown'},1,2))).ok).toBe(true);
  expect((await call(s,'retire',retirement({...record,principal_id:'another'},2,3))).ok).toBe(false);
  expect((await call(s,'retire',retirement(record,2,3))).ok).toBe(true);
  expect(await rows(s,'registry_records')).toHaveLength(1);
  expect(await rows(s,'registry_operations')).toHaveLength(3);
  expect(await rows(s,'registry_retired')).toHaveLength(2);
});
it('retirement capacity: SQL abort preserves the reserved slot and exact operation for retry',async()=>{
  const s=await setup(1,2);expect((await call(s,'register',registration())).ok).toBe(true);
  await runInDurableObject(s,(_i,state)=>{
    state.storage.sql.exec("CREATE TRIGGER retirement_abort BEFORE INSERT ON registry_retired BEGIN SELECT RAISE(ABORT,'retirement SQL fault'); END").toArray();
  });
  expect((await call(s,'retire',retirement())).ok).toBe(false);
  expect((await rows(s,'registry_meta'))[0].revision).toBe(1);
  expect(await rows(s,'registry_operations')).toHaveLength(1);
  await runInDurableObject(s,(_i,state)=>{state.storage.sql.exec('DROP TRIGGER retirement_abort').toArray();});
  expect((await call(s,'retire',retirement({...record,principal_id:'unknown'}))).ok).toBe(false);
  expect((await call(s,'retire',retirement())).ok).toBe(true);
});
it('retirement capacity: post-sync failure and lost registration reply retain capacity for retirement',async()=>{
  const s=await setup(1,2),wire=JSON.stringify({classification:SOURCE,action:'register',input:registration()});
  await runInDurableObject(s,async(instance,state)=>{
    const original=state.storage.sync.bind(state.storage);
    const spy=vi.spyOn(state.storage,'sync').mockImplementation(async()=>{await original();throw Error('lost registration acknowledgement');});
    try{expect(JSON.parse(await instance.sourceCommand(wire)).ok).toBe(false);}finally{spy.mockRestore();}
  });
  const again=env.REGISTRY_DATA.get(s.id);
  expect((await call(again,'retire',retirement({...record,principal_id:'unknown'}))).ok).toBe(false);
  expect((await call(again,'retire',retirement())).ok).toBe(true);
  expect((await call(again,'read',lookup())).ok).toBe(false);
  expect(await rows(again,'registry_operations')).toHaveLength(2);
});
it('a new stub sees original retired state without returning a positive authority lease',async()=>{
  const s=await setup();await call(s,'register',registration());await call(s,'retire',retirement());
  const again=env.REGISTRY_DATA.get(s.id);expect((await call(again,'read',lookup())).ok).toBe(false);
  expect(await rows(again,'registry_operations')).toHaveLength(2);
});
it('duplicate keys, malformed/oversized commands, wrong source label and unknown actions reject',async()=>{
  const s=await setup();for(const raw of ['{','x'.repeat(8193),`{"classification":"${SOURCE}","classification":"${SOURCE}","action":"read","input":{}}`,
    JSON.stringify({classification:'ordinary-pair-token',action:'register',input:registration()}),JSON.stringify({classification:SOURCE,action:'native-send',input:{}})]) {
    expect(JSON.parse(await s.sourceCommand(raw)).ok).toBe(false);
  }expect(await rows(s,'registry_operations')).toHaveLength(0);
});
