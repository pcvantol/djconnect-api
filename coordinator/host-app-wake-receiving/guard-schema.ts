/** Code-pinned source-only local SQL guard admission. Never provisions SQL. */
import {sha256Hex} from '../../src/crypto';
import {need} from '../host-app-wake/wire';
import {RequestWindow} from './request-window';
const expected = {"host_wake_current_verified_targets": "5eacd50207ff929c61ba350299c5f038e72069fe6b5c9be0cf44153f19b8444f", "host_wake_receiving_registration_guard": "e2b08c414eb8262ef0b01a2612aecd8a645d056e26d987f8fb23bc4a6e7f4308", "host_wake_receiving_dispatch_guard": "034951ce476ffdeb0ee3ee19396a3091266ca8202b8dd5943951a3e2ad3faf17", "host_wake_receiving_issuer_guard": "957304357fda9221c3151d24383ae71e5f28735dc1a546f283c6b34ba3ad1d73", "host_wake_native_first_job_guard": "9b0663e6ae8697eefda9030ce076b254818e2090a20f2ed7c0ae2a8c66b43858", "host_wake_native_key_insert_guard": "1072473fc06ca17629dee745c183d9c628f33fc774093435f9177c1c1b545afb", "host_wake_native_first_proof_guard": "48d9ca39f6ff8c01b834f5b86b4dec2b4105c49af69b69b385ae9def71a1ee0d"} as const;
export async function requireReceivingGuards(db:D1Database,window:RequestWindow){
 for(const [name,hash] of Object.entries(expected)){
  const row=await window.run(()=>db.prepare('SELECT sql FROM sqlite_master WHERE name=? AND type IN(?,?)').bind(name,'view','trigger').first<{sql:string}>());
  need(row&&typeof row.sql==='string','host_wake_receiving_schema_unavailable',503);
  const text=row.sql.replace(/--[^\n]*/g,'').trim().replace(/CREATE (VIEW|TRIGGER) IF NOT EXISTS/g,'CREATE $1').replace(/\s+/g,' ').replace(/;$/,'').trim();
  need(await window.run(()=>sha256Hex(text))===hash,'host_wake_receiving_schema_unavailable',503);
 }
}
