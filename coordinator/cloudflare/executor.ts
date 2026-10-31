import type {SourceStateClient} from './rpc';
import {SOURCE, STAGES, fail, integer, flat, jobData, epochData, claimData, type Job, type Epoch, type Claim} from './model';

/** No positive factory, irrespective of config/arguments. No secret/provider dependency. */
export function createProductionCoordinator(..._args: unknown[]): never {
  return fail('management/native/policy/restore/Container/clock/custody unqualified');
}
export interface SyntheticClock { domain: string; continuousNs(): bigint; utcUpperMs(): number }
export interface Admission {
  label: typeof SOURCE; job: Readonly<Job>; epoch: Readonly<Epoch>;
  clockDomain: string; originalCutoffNs: bigint; issuedAtMs: number;
  parentIssuedAtMs: number; parentExpiresAtMs: number;
  operationMaxMs: number; parentMaxMs: number; maxJobs: number;
}
const fixtureAdmissions = new WeakSet<object>();
/** One executor-local handle and final observation boundary; not an APNs sender. */
export class SourceContainerExecutor {
  private retired = false;
  private lastContinuous = -1n;
  private lastUtc = -1;
  private readonly handles = new WeakSet<Admission>();
  readonly observations: {job: string; state: 'SPENT'|'SOURCE_OBSERVATION_ONLY'}[] = [];
  constructor(private readonly state: SourceStateClient, private readonly clock: SyntheticClock,
    private readonly generation: number) { integer(generation); }
  retire(): void { this.retired = true; }
  private guard(a: Admission, signal?: AbortSignal): void {
    if (signal?.aborted) this.retire();
    if (this.retired) fail('cancelled/retired executor');
    if (!fixtureAdmissions.has(a) || a.label !== SOURCE) fail('original immutable source admission required');
    if (this.clock.domain !== a.clockDomain || this.generation !== a.epoch.containerGeneration) {
      this.retire();fail('clock/Container generation');
    }
    for (const n of [a.issuedAtMs,a.parentIssuedAtMs,a.parentExpiresAtMs,a.operationMaxMs,a.parentMaxMs,a.maxJobs]) integer(n);
    if (typeof a.originalCutoffNs !== 'bigint' || a.originalCutoffNs <= 0n
      || a.job.deadline <= a.issuedAtMs || a.job.deadline-a.issuedAtMs > a.operationMaxMs
      || a.parentExpiresAtMs <= a.parentIssuedAtMs || a.parentExpiresAtMs-a.parentIssuedAtMs > a.parentMaxMs
      || a.job.deadline > a.parentExpiresAtMs) fail('original policy/deadline');
    const continuous=this.clock.continuousNs(), utc=this.clock.utcUpperMs(); integer(utc);
    if (typeof continuous !== 'bigint' || continuous < this.lastContinuous || utc < this.lastUtc
      || continuous >= a.originalCutoffNs || utc >= a.job.deadline) { this.retired=true; fail('clock regression/original expiry'); }
    this.lastContinuous=continuous; this.lastUtc=utc;
  }
  async begin(a: Admission, operation: string, nonce: string, signal?: AbortSignal): Promise<void> {
    this.guard(a,signal);
    try { await this.state.createJobData(a.epoch,a.job,operation,nonce,a.maxJobs); this.guard(a,signal); }
    catch (error) { this.retire(); throw error; }
  }
  async step(a: Admission, claim: Claim, signal?: AbortSignal): Promise<void> {
    this.guard(a,signal);
    claim=claimData(claim); // Snapshot before the RPC await and ACK comparison.
    try {
      const wire=await this.state.commitStageData(a.epoch,a.job,claim);
      if (typeof wire !== 'string' || wire.length > 1024) fail('invalid persistence ACK');
      const ack=flat(JSON.parse(wire),['classification','epoch','job','revision','phase']);
      const epoch=epochData(ack.epoch as Epoch);
      this.guard(a,signal);
      if (ack.classification !== SOURCE || ack.job !== a.job.job || epoch.restore !== a.epoch.restore
        || epoch.containerGeneration !== a.epoch.containerGeneration || ack.phase !== STAGES.indexOf(claim.stage)+1
        || ack.revision !== claim.revision+1) fail('unexpected persistence ACK');
      if (claim.stage === 'submit') this.handles.add(a);
    } catch (error) { this.retire(); throw error; } // No retry/new UUID/handle repair after ambiguity.
  }
  async observeFinal(a: Admission, build: () => string, signal?: AbortSignal): Promise<string> {
    if (!this.handles.delete(a)) fail('no original in-process handle'); // Consume BEFORE await/construction.
    try {
      this.guard(a,signal);
      await this.state.validateSpentData(a.epoch,a.job); // Last remote/data hop, never provider submission.
      this.guard(a,signal);
      const record: {job: string; state: 'SPENT'|'SOURCE_OBSERVATION_ONLY'}={job:a.job.job,state:'SPENT'};
      this.observations.push(record);
      const payload=build();
      if (typeof payload !== 'string' || new TextEncoder().encode(payload).length > 16384) fail('invalid source payload');
      this.guard(a,signal); // AFTER construction, same executor, no further await/RPC/provider hop.
      record.state='SOURCE_OBSERVATION_ONLY';
      return payload;
    } catch (error) { this.retire(); throw error; }
  }
}
export function syntheticAdmission(value: Admission): Readonly<Admission> {
  const o=flat(value,['label','job','epoch','clockDomain','originalCutoffNs','issuedAtMs','parentIssuedAtMs',
    'parentExpiresAtMs','operationMaxMs','parentMaxMs','maxJobs']);
  o.job=jobData(o.job as Job); o.epoch=epochData(o.epoch as Epoch);
  if (o.label !== SOURCE || typeof o.clockDomain !== 'string' || !o.clockDomain) fail('source fixture only');
  const admission=Object.freeze({...o}) as unknown as Readonly<Admission>;
  fixtureAdmissions.add(admission);
  return admission;
}
