import {DurableObject} from 'cloudflare:workers';
import {SOURCE, STAGES, Closed, fail, integer, hash, uuid, flat, jobData, claimData, epochData,
  type Job, type Claim, type Epoch, type Ack} from './model';

// Only the qualification Worker exports this class. No root export/binding/migration.
// No D1, KV mirror, Container disk journal, signer, secrets or provider port.
const DDL = `
CREATE TABLE IF NOT EXISTS cf_meta (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL CHECK(version=1), restore TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0)) STRICT;
CREATE TABLE IF NOT EXISTS cf_parents (id TEXT PRIMARY KEY, body TEXT NOT NULL, generation INTEGER NOT NULL, retired INTEGER NOT NULL CHECK(retired IN (0,1))) STRICT;
CREATE TABLE IF NOT EXISTS cf_jobs (id TEXT PRIMARY KEY, parent TEXT NOT NULL REFERENCES cf_parents(id), body TEXT NOT NULL, phase INTEGER NOT NULL, revision INTEGER NOT NULL, retired INTEGER NOT NULL CHECK(retired IN (0,1))) STRICT;
CREATE TABLE IF NOT EXISTS cf_operations (id TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES cf_jobs(id)) STRICT;
CREATE TABLE IF NOT EXISTS cf_nonces (id TEXT PRIMARY KEY, job TEXT NOT NULL REFERENCES cf_jobs(id)) STRICT;
CREATE TABLE IF NOT EXISTS cf_claims (job TEXT NOT NULL REFERENCES cf_jobs(id), stage TEXT NOT NULL, operation TEXT NOT NULL UNIQUE REFERENCES cf_operations(id), body TEXT NOT NULL, PRIMARY KEY(job,stage)) STRICT;
CREATE TABLE IF NOT EXISTS cf_counters (key_ref TEXT PRIMARY KEY, scope TEXT NOT NULL, counter INTEGER NOT NULL CHECK(counter BETWEEN 1 AND 4294967295), revision INTEGER NOT NULL CHECK(revision>0)) STRICT;
`;
type Row = Record<string, SqlStorageValue>;

/** Actual DO SQL + transactionSync + persistence ACK. DATA only. */
export class CoordinatorSourceState extends DurableObject {
  /** Closed source-only RPC envelope. Expected rejections are DATA, never positive ACKs.
   * Strings avoid RPC resource/disposal metadata entering the closed DATA records.
   */
  async sourceCommand(wire: string): Promise<string> {
    try {
      if (typeof wire !== 'string' || wire.length > 16384) fail('invalid source command');
      const c=flat(JSON.parse(wire),['label','method','args']);
      if(c.label !== SOURCE || !Array.isArray(c.args)) fail('source fixture required');
      let result: string | void;
      switch(c.method) {
        case 'initialize': {
          if(c.args.length !== 1) fail('invalid args');
          result=await this.#initializeSourceFixture(SOURCE,c.args[0]);break;
        }
        case 'generation': {
          if(c.args.length !== 1) fail('invalid args');
          result=await this.#advanceContainerGeneration(c.args[0]);break;
        }
        case 'parent': {
          if(c.args.length !== 2) fail('invalid args');
          result=await this.#registerParentData(c.args[0],c.args[1]);break;
        }
        case 'create': {
          if(c.args.length !== 5) fail('invalid args');
          result=await this.#createJobData(c.args[0],c.args[1],c.args[2],c.args[3],c.args[4]);break;
        }
        case 'stage': {
          if(c.args.length !== 3) fail('invalid args');
          result=await this.#commitStageData(c.args[0],c.args[1],c.args[2]);break;
        }
        case 'validate': {
          if(c.args.length !== 2) fail('invalid args');
          result=await this.#validateSpentData(c.args[0],c.args[1]);break;
        }
        case 'retire': {
          if(c.args.length !== 2) fail('invalid args');
          result=await this.#retireParentData(c.args[0],c.args[1]);break;
        }
        default: fail('unknown source command');
      }
      return JSON.stringify({ok:true,value:result ?? null});
    } catch(error) {
      return JSON.stringify({ok:false,error:error instanceof Closed ? error.message : 'source transaction rejected'});
    }
  }
  #rows(query: string, ...bindings: SqlStorageValue[]): Row[] {
    return this.ctx.storage.sql.exec(query, ...bindings).toArray(); // Fully consumed before await.
  }
  #epoch(expected: Epoch): Readonly<Epoch> {
    const e = epochData(expected);
    const m = this.#rows('SELECT * FROM cf_meta WHERE id=1')[0];
    if (!m || m.version !== 1 || m.restore !== e.restore || m.generation !== e.containerGeneration) fail('restore/generation fence');
    return e;
  }
  /** Disposable fixture bootstrap, never a production initializer or restore approval. */
  async #initializeSourceFixture(label: string, restore: string): Promise<string> {
    if (label !== SOURCE) fail('source fixture required'); hash(restore);
    this.ctx.storage.transactionSync(() => {
      this.#rows('PRAGMA foreign_keys=ON');
      this.#rows(DDL);
      if (this.#rows('SELECT * FROM cf_meta').length) fail('already initialized');
      this.#rows('INSERT INTO cf_meta VALUES(1,1,?,1)', restore);
    });
    await this.ctx.storage.sync();
    this.#epoch({restore,containerGeneration:1});
    return JSON.stringify({restore, containerGeneration: 1});
  }
  async #advanceContainerGeneration(expected: Epoch): Promise<string> {
    const e = epochData(expected);
    this.ctx.storage.transactionSync(() => {
      this.#epoch(e); integer(e.containerGeneration + 1);
      this.#rows('UPDATE cf_meta SET generation=generation+1 WHERE id=1');
      this.#rows('UPDATE cf_jobs SET retired=1');
    });
    await this.ctx.storage.sync();
    this.#epoch({...e,containerGeneration:e.containerGeneration+1});
    return JSON.stringify({...e, containerGeneration: e.containerGeneration + 1});
  }
  async #registerParentData(expected: Epoch, input: Job): Promise<void> {
    const e = epochData(expected), job = jobData(input);
    const parent = JSON.stringify({parent:job.parent,generation:job.parentGeneration,pairingEpoch:job.pairingEpoch,
      principalEpoch:job.principalEpoch,role:job.role});
    this.ctx.storage.transactionSync(() => {
      this.#epoch(e);
      this.#rows('INSERT INTO cf_parents VALUES(?,?,?,0)', job.parent, parent, job.parentGeneration);
    });
    await this.ctx.storage.sync();
  }
  #current(expected: Epoch, input: Job): Row {
    this.#epoch(expected);
    const row = this.#rows('SELECT j.*,p.body AS parent_body,p.generation AS parent_generation,p.retired AS parent_retired FROM cf_jobs j JOIN cf_parents p ON p.id=j.parent WHERE j.id=?', input.job)[0];
    if (!row || row.body !== JSON.stringify(input) || row.retired !== 0 || row.parent_retired !== 0 || row.parent_generation !== input.parentGeneration) fail('original job/parent fence');
    const parent = JSON.stringify({parent:input.parent,generation:input.parentGeneration,pairingEpoch:input.pairingEpoch,
      principalEpoch:input.principalEpoch,role:input.role});
    if (row.parent_body !== parent) fail('original parent context');
    return row;
  }
  async #createJobData(expected: Epoch, input: Job, operation: string, nonce: string, maxJobs: number): Promise<void> {
    const e = epochData(expected), job = jobData(input); uuid(operation); hash(nonce); integer(maxJobs);
    this.ctx.storage.transactionSync(() => {
      this.#epoch(e);
      const p = this.#rows('SELECT * FROM cf_parents WHERE id=?',job.parent)[0];
      if (!p || p.retired !== 0 || p.generation !== job.parentGeneration) fail('parent fence');
      if (Number(this.#rows('SELECT count(*) AS n FROM cf_jobs')[0].n) >= maxJobs) fail('source job budget');
      this.#rows('INSERT INTO cf_jobs VALUES(?,?,?,0,1,0)',job.job,job.parent,JSON.stringify(job));
      this.#current(e,job);
      this.#rows('INSERT INTO cf_operations VALUES(?,?)',operation,job.job);
      this.#rows('INSERT INTO cf_nonces VALUES(?,?)',nonce,job.job);
    });
    await this.ctx.storage.sync();
    this.#current(e,job);
  }
  async #commitStageData(expected: Epoch, input: Job, data: Claim): Promise<string> {
    const e = epochData(expected), job = jobData(input), claim = claimData(data);
    this.ctx.storage.transactionSync(() => {
      const row = this.#current(e,job), stage = STAGES.indexOf(claim.stage);
      if (row.phase !== stage || row.revision !== claim.revision) fail('stage/revision CAS');
      this.#rows('INSERT INTO cf_operations VALUES(?,?)',claim.operation,job.job);
      this.#rows('INSERT INTO cf_nonces VALUES(?,?)',claim.nonce,job.job);
      this.#rows('INSERT INTO cf_claims VALUES(?,?,?,?)',job.job,claim.stage,claim.operation,claim.body);
      if (claim.counter !== null) {
        const c = this.#rows('SELECT * FROM cf_counters WHERE key_ref=?',job.keyRef)[0];
        if (c) {
          if (c.scope !== job.keyScope || c.revision !== claim.counterRevision || Number(c.counter) >= claim.counter) fail('global key counter CAS');
          this.#rows('UPDATE cf_counters SET counter=?,revision=revision+1 WHERE key_ref=?',claim.counter,job.keyRef);
        } else {
          if (claim.counterRevision !== 0) fail('initial counter CAS');
          this.#rows('INSERT INTO cf_counters VALUES(?,?,?,1)',job.keyRef,job.keyScope,claim.counter);
        }
      }
      this.#rows('UPDATE cf_jobs SET phase=phase+1,revision=revision+1 WHERE id=?',job.job);
    });
    // If this rejects or its RPC reply is lost, the caller MUST treat outcome as unknown.
    // Never describe a completed transaction as rolled back after this boundary.
    await this.ctx.storage.sync();
    const current=this.#current(e,job);
    if(current.phase!==STAGES.indexOf(claim.stage)+1 || current.revision!==claim.revision+1)fail('changed during persistence ACK');
    return JSON.stringify({classification:SOURCE,epoch:e,job:job.job,revision:claim.revision+1,phase:STAGES.indexOf(claim.stage)+1} satisfies Ack);
  }
  async #validateSpentData(expected: Epoch, input: Job): Promise<void> {
    const e = epochData(expected), job = jobData(input);
    this.ctx.storage.transactionSync(() => {
      const row = this.#current(e,job);
      if (row.phase !== STAGES.length || row.revision !== STAGES.length+1) fail('not submit spent');
    });
    await this.ctx.storage.sync();
    const current=this.#current(e,job);
    if(current.phase!==STAGES.length || current.revision!==STAGES.length+1)fail('changed during persistence ACK');
  }
  async #retireParentData(expected: Epoch, parent: string): Promise<void> {
    const e = epochData(expected); uuid(parent);
    this.ctx.storage.transactionSync(() => {
      this.#epoch(e);
      this.#rows('UPDATE cf_parents SET retired=1 WHERE id=?',parent);
      this.#rows('UPDATE cf_jobs SET retired=1 WHERE parent=?',parent);
    });
    await this.ctx.storage.sync();
  }
  /** Intentionally unavailable before reading ctx.container or starting any process. */
  startProductionContainer(): never { return fail('production Container/image/clock/custody unavailable'); }
  /** Source wiring only. Never called by the unavailable production start method.
   * The named export is real in the qualification worker, absent from the root Worker.
   */
  async configureSourceInterception():Promise<void> {
    const container=this.ctx.container;if(!container)fail('source Container absent');
    const loopback=this.ctx.exports as unknown as {
      SourceStateOutbound(options:{props:{stateId:string}}):Fetcher;
    };
    const handler=loopback.SourceStateOutbound({props:{stateId:this.ctx.id.toString()}});
    // Port 80 to all other hosts is rejected by the same handler. Other protocols
    // must remain blocked by enableInternet:false in a future reviewed start path.
    await container.interceptAllOutboundHttp(handler);
  }
}
