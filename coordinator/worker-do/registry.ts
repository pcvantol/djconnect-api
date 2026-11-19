import {DurableObject} from 'cloudflare:workers';
import {SOURCE,need,closed,id,hash,integer,operation,registryData,parseStrictJson,type RegistryData} from './model';

const DDL=`
CREATE TABLE IF NOT EXISTS registry_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL CHECK(version=1),restore TEXT NOT NULL,revision INTEGER NOT NULL,max_records INTEGER NOT NULL,max_operations INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS registry_heads(principal TEXT PRIMARY KEY,epoch INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS registry_records(principal TEXT NOT NULL,epoch INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(principal,epoch)) STRICT;
CREATE TABLE IF NOT EXISTS registry_retired(principal TEXT NOT NULL,epoch INTEGER NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(principal,epoch)) STRICT;
CREATE TABLE IF NOT EXISTS registry_operations(operation TEXT PRIMARY KEY,nonce TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,revision INTEGER NOT NULL) STRICT;
`;
type Row=Record<string,SqlStorageValue>;
/** One real SQLite DO transaction domain. Exported only by the source qualification Worker. */
export class PrincipalRegistryData extends DurableObject {
  #sql(sql:string,...args:SqlStorageValue[]):Row[] {return this.ctx.storage.sql.exec(sql,...args).toArray();}
  #meta(restore:unknown,expectedRevision?:unknown):Row {
    hash(restore);if(expectedRevision!==undefined)integer(expectedRevision,0);
    const m=this.#sql('SELECT * FROM registry_meta WHERE id=1')[0];
    need(m?.version===1 && m.restore===restore,'restore fence');
    if(expectedRevision!==undefined)need(m.revision===expectedRevision,'registry revision CAS');
    return m;
  }
  #reserve(m:Row,op:unknown,nonce:unknown,kind:string,retiring?:{principal_id:string;principal_epoch:number}):number {
    operation(op);hash(nonce);
    const used=Number(this.#sql('SELECT count(*) AS n FROM registry_operations')[0].n);
    // Every stored unretired epoch keeps one operation slot for its own retirement.
    // Counts and reservation share the mutation transaction; no in-memory credit or pruning.
    const pending=Number(this.#sql(`SELECT count(*) AS n FROM registry_records r
      WHERE NOT EXISTS(SELECT 1 FROM registry_retired t WHERE t.principal=r.principal AND t.epoch=r.epoch)`)[0].n);
    const released=retiring && this.#sql(`SELECT 1 FROM registry_records r WHERE r.principal=? AND r.epoch=?
      AND NOT EXISTS(SELECT 1 FROM registry_retired t WHERE t.principal=r.principal AND t.epoch=r.epoch)`,
      retiring.principal_id,retiring.principal_epoch).length===1 ? 1 : 0;
    need(Number(m.max_operations)-used>=1+pending+(kind==='register'?1:0)-released,'operation capacity including retirement');
    const next=Number(m.revision)+1;integer(next);
    this.#sql('INSERT INTO registry_operations VALUES(?,?,?,?)',op,nonce,kind,next);
    this.#sql('UPDATE registry_meta SET revision=? WHERE id=1',next);return next;
  }
  /** String envelope avoids RPC disposal metadata. The label is a fixture marker, NOT auth. */
  async sourceCommand(wire:string):Promise<string> {
    try {
      need(typeof wire==='string' && new TextEncoder().encode(wire).length<=8192,'command cap');
      const c=parseStrictJson(wire);closed(c,['classification','action','input']);need(c.classification===SOURCE,'source fixture only');
      let result:unknown;
      if(c.action==='initialize')result=await this.#initialize(c.input);
      else if(c.action==='register')result=await this.#register(c.input);
      else if(c.action==='retire')result=await this.#retire(c.input);
      else if(c.action==='read')result=await this.#read(c.input);
      else throw new Error('unknown source action');
      return JSON.stringify({classification:SOURCE,ok:true,result});
    } catch {
      // Includes possible post-commit sync/read failure: negative DATA, never rollback claim.
      return JSON.stringify({classification:SOURCE,ok:false,error:'source_registry_unavailable'});
    }
  }
  async #initialize(input:unknown):Promise<unknown> {
    closed(input,['restore','max_records','max_operations']);hash(input.restore);integer(input.max_records);integer(input.max_operations);
    this.ctx.storage.transactionSync(()=>{
      this.#sql(DDL);need(this.#sql('SELECT * FROM registry_meta').length===0,'already initialized');
      this.#sql('INSERT INTO registry_meta VALUES(1,1,?,0,?,?)',input.restore as string,input.max_records as number,input.max_operations as number);
    });
    await this.ctx.storage.sync();const m=this.#meta(input.restore);return {revision:m.revision};
  }
  async #register(input:unknown):Promise<unknown> {
    closed(input,['restore','expected_revision','operation_id','nonce_sha256','record']);
    // Snapshot/validate all bytes before async crypto; no caller-supplied verifier callback.
    const {record,body,digest}=await registryData(input.record);
    let revision=0;
    this.ctx.storage.transactionSync(()=>{
      const m=this.#meta(input.restore,input.expected_revision);
      need(Number(this.#sql('SELECT count(*) AS n FROM registry_records')[0].n)<Number(m.max_records),'record capacity');
      need(this.#sql('SELECT * FROM registry_retired WHERE principal=? AND epoch=?',record.principal_id,record.principal_epoch).length===0,'retired epoch');
      const head=this.#sql('SELECT epoch FROM registry_heads WHERE principal=?',record.principal_id)[0];
      if(head) {
        need(record.principal_epoch===Number(head.epoch)+1,'epoch order');
        need(this.#sql('SELECT * FROM registry_retired WHERE principal=? AND epoch=?',record.principal_id,head.epoch).length===1,'prior epoch not retired');
      } else need(record.principal_epoch===1,'initial epoch');
      revision=this.#reserve(m,input.operation_id,input.nonce_sha256,'register');
      this.#sql('INSERT INTO registry_records VALUES(?,?,?,?,?)',record.principal_id,record.principal_epoch,body,digest,revision);
      this.#sql('INSERT INTO registry_heads VALUES(?,?) ON CONFLICT(principal) DO UPDATE SET epoch=excluded.epoch',record.principal_id,record.principal_epoch);
    });
    await this.ctx.storage.sync();this.#meta(input.restore,revision);
    need(this.#sql('SELECT * FROM registry_retired WHERE principal=? AND epoch=?',record.principal_id,record.principal_epoch).length===0,'retired during ACK');
    return {revision,record_sha256:digest,state:'STORED_SOURCE_DATA'};
  }
  async #retire(input:unknown):Promise<unknown> {
    closed(input,['restore','expected_revision','operation_id','nonce_sha256','principal_id','principal_epoch']);
    id(input.principal_id);integer(input.principal_epoch);let revision=0;
    this.ctx.storage.transactionSync(()=>{
      const m=this.#meta(input.restore,input.expected_revision);
      revision=this.#reserve(m,input.operation_id,input.nonce_sha256,'retire',{
        principal_id:input.principal_id as string,principal_epoch:input.principal_epoch as number});
      // Negative tombstone also works before registration. No time-based deletion/reopening.
      this.#sql('INSERT INTO registry_retired VALUES(?,?,?)',input.principal_id as string,input.principal_epoch as number,revision);
      this.#sql('INSERT INTO registry_heads VALUES(?,?) ON CONFLICT(principal) DO UPDATE SET epoch=max(epoch,excluded.epoch)',input.principal_id as string,input.principal_epoch as number);
    });
    await this.ctx.storage.sync();this.#meta(input.restore,revision);
    return {revision,state:'RETIRED_SOURCE_DATA'};
  }
  async #read(input:unknown):Promise<unknown> {
    closed(input,['restore','principal_id','principal_epoch','core_instance_id','installation_id','accepted_pair_binding_sha256','purpose']);
    id(input.principal_id);integer(input.principal_epoch);id(input.core_instance_id);id(input.installation_id);hash(input.accepted_pair_binding_sha256);
    let result:unknown;
    this.ctx.storage.transactionSync(()=>{
      const m=this.#meta(input.restore);
      const row=this.#sql('SELECT * FROM registry_records WHERE principal=? AND epoch=?',input.principal_id as string,input.principal_epoch as number)[0];
      need(row,'unknown source record');
      need(this.#sql('SELECT * FROM registry_retired WHERE principal=? AND epoch=?',input.principal_id as string,input.principal_epoch as number).length===0,'retired');
      const record=JSON.parse(row.body as string) as RegistryData;
      for(const key of ['core_instance_id','installation_id','accepted_pair_binding_sha256'] as const)need(record[key]===input[key],'scope mismatch');
      need(typeof input.purpose==='string' && record.allowed_purposes.includes(input.purpose as RegistryData['allowed_purposes'][number]),'purpose mismatch');
      result={revision:m.revision,record_sha256:row.digest,state:'STORED_SOURCE_DATA',record};
    });
    // No write/async/provider hop here: a point-in-time DATA read, not a validity lease.
    return result;
  }
}
