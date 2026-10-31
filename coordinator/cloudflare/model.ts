/** Closed DATA fixtures, never management/native admission or a signed grant. */
export const SOURCE = 'SYNTHETIC_SOURCE_QUALIFICATION' as const;
export class Closed extends Error {}
export function fail(message: string): never { throw new Closed(message); }
export function integer(n: unknown, min = 1, max = Number.MAX_SAFE_INTEGER - 1): asserts n is number {
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < min || n > max) fail('invalid integer');
}
export function hash(s: unknown): asserts s is string {
  if (typeof s !== 'string' || !/^[a-f0-9]{64}$/.test(s)) fail('invalid hash');
}
export function uuid(s: unknown): asserts s is string {
  if (typeof s !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(s)) fail('invalid UUID');
}
export function flat(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || ![null, Object.prototype].includes(Object.getPrototypeOf(value))) fail('invalid record');
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value as object).length !== keys.length) fail('extra/missing fields');
  const out: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    const d = descriptors[key];
    if (!d || !('value' in d) || !d.enumerable) fail('accessor/missing field');
    out[key] = d.value;
  }
  return out;
}
export interface Job {
  job: string; parent: string; parentGeneration: number; pairingEpoch: string; principalEpoch: number;
  role: 'widget_transport' | 'status_activity_transport'; context: string;
  keyScope: string; keyRef: string; deadline: number;
}
const JOB_KEYS = ['job','parent','parentGeneration','pairingEpoch','principalEpoch','role','context','keyScope','keyRef','deadline'] as const;
export function jobData(value: Job): Readonly<Job> {
  const o = flat(value, JOB_KEYS);
  uuid(o.job); uuid(o.parent); hash(o.pairingEpoch); hash(o.context); hash(o.keyScope); hash(o.keyRef);
  integer(o.parentGeneration); integer(o.principalEpoch); integer(o.deadline);
  if (o.role !== 'widget_transport' && o.role !== 'status_activity_transport') fail('invalid role');
  return Object.freeze({...o}) as unknown as Readonly<Job>;
}
export type Stage = 'prepare_key' | 'verify_key' | 'prepare_target' | 'verify_target' | 'submit';
export const STAGES: readonly Stage[] = ['prepare_key','verify_key','prepare_target','verify_target','submit'];
export interface Claim {
  operation: string; nonce: string; body: string; stage: Stage; revision: number;
  counter: number | null; counterRevision: number | null;
}
export function claimData(value: Claim): Readonly<Claim> {
  const o = flat(value, ['operation','nonce','body','stage','revision','counter','counterRevision']);
  uuid(o.operation); hash(o.nonce); hash(o.body); integer(o.revision);
  if (!STAGES.includes(o.stage as Stage)) fail('invalid stage');
  const verifies = o.stage === 'verify_key' || o.stage === 'verify_target';
  if (verifies) { integer(o.counter, 1, 4294967295); integer(o.counterRevision, 0); }
  else if (o.counter !== null || o.counterRevision !== null) fail('unexpected counter');
  return Object.freeze({...o}) as unknown as Readonly<Claim>;
}
export interface Epoch { restore: string; containerGeneration: number }
export function epochData(value: Epoch): Readonly<Epoch> {
  const o = flat(value, ['restore','containerGeneration']); hash(o.restore); integer(o.containerGeneration);
  return Object.freeze({...o}) as unknown as Readonly<Epoch>;
}
export interface Ack { classification: typeof SOURCE; epoch: Readonly<Epoch>; job: string; revision: number; phase: number }
