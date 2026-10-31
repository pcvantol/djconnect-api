/** Code-pinned source-only local SQL guard admission. Never provisions SQL. */
import {sha256Hex} from '../../src/crypto';
import {need} from '../host-app-wake/wire';
import {RequestWindow} from './request-window';
const expected = {"host_wake_receiving_issuer_guard": "957304357fda9221c3151d24383ae71e5f28735dc1a546f283c6b34ba3ad1d73", "host_wake_current_verified_targets": "2754c328d1558d6a7c51c7892a59c6f90912305fff4be874bccb35f4deb62466", "host_wake_receiving_registration_guard": "e2b08c414eb8262ef0b01a2612aecd8a645d056e26d987f8fb23bc4a6e7f4308", "host_wake_receiving_dispatch_guard": "034951ce476ffdeb0ee3ee19396a3091266ca8202b8dd5943951a3e2ad3faf17"} as const;
export async function requireReceivingGuards(db:D1Database,window:RequestWindow){
 for(const [name,hash] of Object.entries(expected)){
  const row=await window.run(()=>db.prepare('SELECT sql FROM sqlite_master WHERE name=? AND type IN(?,?)').bind(name,'view','trigger').first<{sql:string}>());
  need(row&&typeof row.sql==='string','host_wake_receiving_schema_unavailable',503);
  const text=row.sql.replace(/--[^\n]*/g,'').trim().replace(/CREATE (VIEW|TRIGGER) IF NOT EXISTS/g,'CREATE $1').replace(/\s+/g,' ').replace(/;$/,'').trim();
  need(await window.run(()=>sha256Hex(text))===hash,'host_wake_receiving_schema_unavailable',503);
 }
}
