/** Uncomposed D1 DATA repository. No native verdict, owner admission or qualified clock. */
export const NATIVE_PROOF_DATA_CLASSIFICATION = "DATA_ONLY_NOT_ADMISSION" as const;
export type DataStage = "prepare_key" | "verify_key" | "prepare_target" | "verify_target";
export type DataRetirement = "REJECTED_RETIRED" | "WITHDRAWN_RETIRED" | "EXPIRED_RETIRED" | "UNCERTAIN_RETIRED";
export interface DataJobInput {
 job_id: string; bootstrap_binding_sha256: string; context_sha256: string; key_scope_sha256: string;
 key_operation_id: string; target_operation_id: string; key_nonce_sha256: string; target_nonce_sha256: string;
 bootstrap_deadline_unix_ms: number; original_grant_expires_at_unix_ms: number;
}
export interface DataStageInput {
 job_id: string; context_sha256: string; stage: DataStage; expected_revision: number;
 operation_id: string; nonce_sha256: string; body_sha256: string;
}
export type DataCompletion =
 | { stage: "prepare_key"; key_mode: "new_key_attestation"; key_ref_sha256: null; transcript_sha256: string }
 | { stage: "prepare_key"; key_mode: "existing_key_assertion"; key_ref_sha256: string; transcript_sha256: string }
 | { stage: "prepare_target"; transcript_sha256: string; native_token_sha256: string }
 | { stage: "verify_key" | "verify_target"; transcript_sha256: string; key_ref_sha256: string;
     counter: number; expected_counter_revision: number | null };
declare const reservationBrand: unique symbol;
export type DataReservation = Readonly<{ classification: typeof NATIVE_PROOF_DATA_CLASSIFICATION; [reservationBrand]: true }>;
export interface DataCommit {
 readonly classification: typeof NATIVE_PROOF_DATA_CLASSIFICATION;
 readonly job_id: string; readonly phase: string; readonly revision: number;
}
export class NativeProofDataError extends Error {
 constructor(readonly code: "invalid_data" | "data_conflict" | "reservation_spent_or_foreign" | "journal_closed" | "job_retired" | "operation_aborted") {
  super(code); this.name = "NativeProofDataError";
 }
}
type Flat = Record<string, unknown>;
type Job = DataJobInput & { data_epoch_sha256: string; phase: string; revision: number; active_claim: string | null;
 last_commit_claim: string | null; key_mode: string | null; key_ref_sha256: string | null;
 key_transcript_sha256: string | null; target_transcript_sha256: string | null; native_token_sha256: string | null };
type Held = { job: Job; stage: DataStage; claim: string; used: boolean };
const JOBS = "native_proof_data_jobs", CLAIMS = "native_proof_data_claims", NONCES = "native_proof_data_nonces";
const COUNTERS = "native_proof_data_key_counters";
const MAX = Number.MAX_SAFE_INTEGER;
const stages = {
 prepare_key: ["APPROVED_AVAILABLE", "APPROVED_AVAILABLE", "KEY_PREPARED", "key"],
 verify_key: ["KEY_PREPARED", "KEY_VERIFYING", "KEY_VERIFIED", "key"],
 prepare_target: ["KEY_VERIFIED", "KEY_VERIFIED", "TARGET_PREPARED", "target"],
 verify_target: ["TARGET_PREPARED", "TARGET_VERIFYING", "TARGET_VERIFIED", "target"],
} as const;
const retirements: readonly string[] = ["REJECTED_RETIRED", "WITHDRAWN_RETIRED", "EXPIRED_RETIRED", "UNCERTAIN_RETIRED"];
function invalid(): never { throw new NativeProofDataError("invalid_data"); }
function hash(v: unknown): asserts v is string { if (typeof v !== "string" || !/^[a-f0-9]{64}$/.test(v)) invalid(); }
function uuid(v: unknown): asserts v is string { if (typeof v !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v)) invalid(); }
function integer(v: unknown, min = 1, max = MAX): asserts v is number {
 if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) invalid();
}
// Reject accessors, extra fields, symbols and inherited values; snapshot once before any await.
function flat(value: unknown, keys: string[]): Flat {
 if (!value || typeof value !== "object" || ![null, Object.prototype].includes(Object.getPrototypeOf(value))) invalid();
 const descriptors = Object.getOwnPropertyDescriptors(value);
 if (Reflect.ownKeys(value).length !== keys.length || keys.some(k => !Object.hasOwn(descriptors, k))) invalid();
 const out: Flat = Object.create(null);
 for (const key of keys) { const d = descriptors[key]; if (!("value" in d) || !d.enumerable) invalid(); out[key] = d.value; }
 return out;
}
const jobKeys = ["job_id", "bootstrap_binding_sha256", "context_sha256", "key_scope_sha256", "key_operation_id", "target_operation_id", "key_nonce_sha256", "target_nonce_sha256", "bootstrap_deadline_unix_ms", "original_grant_expires_at_unix_ms"];
function jobInput(value: DataJobInput): DataJobInput {
 const o = flat(value, jobKeys);
 for (const k of ["job_id", "key_operation_id", "target_operation_id"]) uuid(o[k]);
 for (const k of ["bootstrap_binding_sha256", "context_sha256", "key_scope_sha256", "key_nonce_sha256", "target_nonce_sha256"]) hash(o[k]);
 integer(o.bootstrap_deadline_unix_ms); integer(o.original_grant_expires_at_unix_ms);
 if (o.key_operation_id === o.target_operation_id || o.key_nonce_sha256 === o.target_nonce_sha256) invalid();
 return o as unknown as DataJobInput;
}
function stageInput(value: DataStageInput): DataStageInput {
 const o = flat(value, ["job_id", "context_sha256", "stage", "expected_revision", "operation_id", "nonce_sha256", "body_sha256"]);
 uuid(o.job_id); uuid(o.operation_id); hash(o.context_sha256); hash(o.nonce_sha256); hash(o.body_sha256); integer(o.expected_revision, 1, MAX - 2);
 if (typeof o.stage !== "string" || !Object.hasOwn(stages, o.stage)) invalid();
 return o as unknown as DataStageInput;
}
function completionInput(value: DataCompletion, held: Held): DataCompletion {
 // Read stage through a descriptor, not through a caller getter.
 if (!value || typeof value !== "object") invalid();
 const stage = Object.getOwnPropertyDescriptor(value, "stage")?.value;
 if (stage !== held.stage) invalid();
 const keys = stage === "prepare_key" ? ["stage", "key_mode", "key_ref_sha256", "transcript_sha256"]
  : stage === "prepare_target" ? ["stage", "transcript_sha256", "native_token_sha256"]
  : ["stage", "transcript_sha256", "key_ref_sha256", "counter", "expected_counter_revision"];
 const o = flat(value, keys); hash(o.transcript_sha256);
 if (stage === "prepare_key") {
  if (o.key_mode === "new_key_attestation") { if (o.key_ref_sha256 !== null) invalid(); }
  else if (o.key_mode === "existing_key_assertion") hash(o.key_ref_sha256); else invalid();
 } else if (stage === "prepare_target") hash(o.native_token_sha256);
 else {
  hash(o.key_ref_sha256); integer(o.counter, 0, 4294967295);
  if (stage === "verify_key" && held.job.key_mode === "new_key_attestation") {
   if (o.counter !== 0 || o.expected_counter_revision !== null) invalid();
  } else {
   integer(o.expected_counter_revision, 1, MAX - 1);
   if (o.key_ref_sha256 !== held.job.key_ref_sha256) invalid();
  }
  const prepared = stage === "verify_key" ? held.job.key_transcript_sha256 : held.job.target_transcript_sha256;
  if (o.transcript_sha256 !== prepared) invalid();
 }
 return o as unknown as DataCompletion;
}

/** No schema creation and no default DB/factory. Caller-supplied hashes/deadlines are DATA only. */
export function createNativeProofDataJournal(db: D1Database, dataEpochSha256: string) {
 hash(dataEpochSha256);
 const session = db.withSession("first-primary");
 const held = new WeakMap<object, Held>();
 const retired = new Set<string>();
 let closed = false;
 function guard(signal?: AbortSignal) {
  if (closed) throw new NativeProofDataError("journal_closed");
  if (signal !== undefined && !(signal instanceof AbortSignal)) invalid();
  if (signal?.aborted) throw new NativeProofDataError("operation_aborted");
 }
 const scope = (j: { job_id: string; context_sha256: string }) => j.job_id + "/" + j.context_sha256;
 function guardJob(j: { job_id: string; context_sha256: string }, signal?: AbortSignal) {
  guard(signal); if (retired.has(scope(j))) throw new NativeProofDataError("job_retired");
 }
 const sql = (source: string, ...values: (string | number | null)[]) => session.prepare(source).bind(...values);
 async function batch(statements: D1PreparedStatement[], signal?: AbortSignal, j?: { job_id: string; context_sha256: string }) {
  if (j) guardJob(j, signal); else guard(signal); // No await between guard and submission.
  const result = await session.batch(statements);
  if (j) guardJob(j, signal); else guard(signal); // Suppression does not undo a commit.
  return result;
 }
 function take(reservation: DataReservation, signal?: AbortSignal): Held {
  const h = reservation && typeof reservation === "object" ? held.get(reservation) : undefined;
  if (!h || h.used) throw new NativeProofDataError("reservation_spent_or_foreign");
  h.used = true; // Consume BEFORE validation, guard or any await; never restored on error.
  guardJob(h.job, signal); return h;
 }
 function commitResult(row: Job | undefined): DataCommit {
  if (!row) throw new NativeProofDataError("data_conflict");
  return Object.freeze({ classification: NATIVE_PROOF_DATA_CLASSIFICATION, job_id: row.job_id, phase: row.phase, revision: row.revision });
 }
 // Invariant aborts partial writes INSIDE the transaction, including zero-row CAS losses.
 function atomic(claim: string, markers: string[]): D1PreparedStatement[] {
  return [sql(`INSERT INTO native_proof_data_atomic_checks(claim_id,valid) VALUES (?,CASE WHEN
   ((${markers.join(") AND (")})) OR ((NOT (${markers.join(")) AND (NOT (")}))) THEN 1 ELSE 0 END)`, claim),
   sql("DELETE FROM native_proof_data_atomic_checks WHERE claim_id=?", claim)];
 }
 function owned(h: Held): { predicate: string; bindings: (string | number)[] } {
  return { predicate: `job_id=? AND context_sha256=? AND data_epoch_sha256=? AND revision=? AND active_claim=? AND phase=?
   AND EXISTS(SELECT 1 FROM ${CLAIMS} c WHERE c.job_id=${JOBS}.job_id AND c.claim_id=? AND c.stage=? AND c.outcome='reserved' AND c.claimed_revision=?)`,
   bindings: [h.job.job_id, h.job.context_sha256, dataEpochSha256, h.job.revision, h.claim, stages[h.stage][1], h.claim, h.stage, h.job.revision] };
 }
 function jobMarker(claim: string): string { return `EXISTS(SELECT 1 FROM ${JOBS} WHERE last_commit_claim='${claim}')`; }
 function claimMarker(claim: string, outcome: string): string { return `EXISTS(SELECT 1 FROM ${CLAIMS} WHERE claim_id='${claim}' AND outcome='${outcome}')`; }
 // Only internally generated canonical UUIDs enter marker SQL; all external values are bound.
 function privateClaim(): string { const id = crypto.randomUUID(); uuid(id); return id; }
 function final(h: Held, phase: string, revision: number) {
  return sql(`SELECT * FROM ${JOBS} WHERE job_id=? AND context_sha256=? AND data_epoch_sha256=? AND last_commit_claim=? AND phase=? AND revision=?`,
   h.job.job_id, h.job.context_sha256, dataEpochSha256, h.claim, phase, revision);
 }
 return Object.freeze({
  close() { closed = true; },
  async createDataJob(input: DataJobInput, signal?: AbortSignal): Promise<DataCommit> {
   guard(signal); const j = jobInput(input); guardJob(j, signal);
   const statements = [sql(`INSERT INTO ${JOBS} (${jobKeys.join(",")},data_epoch_sha256,phase,revision) VALUES (${jobKeys.map(() => "?").join(",")},?,'APPROVED_AVAILABLE',1)`,
    ...jobKeys.map(k => (j as unknown as Record<string, string | number>)[k]), dataEpochSha256)];
   for (const role of ["key", "target"] as const) {
    statements.push(sql("INSERT INTO native_proof_data_operations(operation_id,job_id,original_phase) VALUES(?,?,?)", j[`${role}_operation_id`], j.job_id, role));
    statements.push(sql(`INSERT INTO ${NONCES}(nonce_sha256,job_id,original_phase,state) VALUES(?,?,?,'available')`, j[`${role}_nonce_sha256`], j.job_id, role));
   }
   statements.push(sql(`SELECT * FROM ${JOBS} WHERE job_id=? AND context_sha256=? AND data_epoch_sha256=?`, j.job_id, j.context_sha256, dataEpochSha256));
   const result = await batch(statements, signal, j); guardJob(j, signal);
   return commitResult(result.at(-1)?.results[0] as Job | undefined);
  },
  async reserveDataStage(input: DataStageInput, signal?: AbortSignal): Promise<DataReservation> {
   guard(signal); const i = stageInput(input); guardJob(i, signal); const claim = privateClaim();
   const [before, pending, , role] = stages[i.stage], verify = i.stage.startsWith("verify_");
   const statements = [sql(`INSERT INTO ${CLAIMS}(job_id,stage,claim_id,operation_id,body_sha256,claimed_revision,outcome)
    SELECT job_id,?,?,?,?,revision+1,'reserved' FROM ${JOBS}
    WHERE job_id=? AND context_sha256=? AND data_epoch_sha256=? AND revision=? AND revision<? AND phase=? AND active_claim IS NULL
    AND ${role}_operation_id=? AND ${role}_nonce_sha256=?
    AND EXISTS(SELECT 1 FROM ${NONCES} n WHERE n.job_id=${JOBS}.job_id AND n.original_phase=? AND n.nonce_sha256=? AND n.state='available')
    AND NOT EXISTS(SELECT 1 FROM ${CLAIMS} c WHERE c.job_id=${JOBS}.job_id AND c.stage=?)`,
    i.stage, claim, i.operation_id, i.body_sha256, i.job_id, i.context_sha256, dataEpochSha256, i.expected_revision, MAX, before,
    i.operation_id, i.nonce_sha256, role, i.nonce_sha256, i.stage)];
   if (verify) statements.push(sql(`UPDATE ${NONCES} SET state='spent',spent_claim=? WHERE job_id=? AND original_phase=? AND state='available'
    AND EXISTS(SELECT 1 FROM ${CLAIMS} c WHERE c.claim_id=? AND c.outcome='reserved')`, claim, i.job_id, role, claim));
   statements.push(sql(`UPDATE ${JOBS} SET phase=?,revision=revision+1,active_claim=? WHERE job_id=? AND context_sha256=? AND data_epoch_sha256=?
    AND revision=? AND phase=? AND active_claim IS NULL AND EXISTS(SELECT 1 FROM ${CLAIMS} c WHERE c.claim_id=? AND c.outcome='reserved')`,
    pending, claim, i.job_id, i.context_sha256, dataEpochSha256, i.expected_revision, before, claim));
   const markers = [claimMarker(claim, "reserved"), `EXISTS(SELECT 1 FROM ${JOBS} WHERE active_claim='${claim}')`];
   if (verify) markers.push(`EXISTS(SELECT 1 FROM ${NONCES} WHERE spent_claim='${claim}')`);
   statements.push(...atomic(claim, markers), sql(`SELECT * FROM ${JOBS} WHERE active_claim=? AND revision=? AND phase=?`, claim, i.expected_revision + 1, pending));
   const result = await batch(statements, signal, i); guardJob(i, signal);
   const job = result.at(-1)?.results[0] as Job | undefined;
   if (!job) throw new NativeProofDataError("data_conflict");
   const reservation = Object.freeze({ classification: NATIVE_PROOF_DATA_CLASSIFICATION }) as DataReservation;
   held.set(reservation, { job, stage: i.stage, claim, used: false }); guardJob(i, signal); return reservation;
  },
  async completeDataStage(reservation: DataReservation, completion: DataCompletion, signal?: AbortSignal): Promise<DataCommit> {
   const h = take(reservation, signal), c = completionInput(completion, h), own = owned(h), statements: D1PreparedStatement[] = [];
   const markers = [jobMarker(h.claim), claimMarker(h.claim, "committed")];
   let setters: string, values: (string | number | null)[], counterCondition = "";
   if (c.stage === "prepare_key") {
    setters = "key_mode=?,key_ref_sha256=?,key_transcript_sha256=?"; values = [c.key_mode, c.key_ref_sha256, c.transcript_sha256];
   } else if (c.stage === "prepare_target") {
    setters = "target_transcript_sha256=?,native_token_sha256=?"; values = [c.transcript_sha256, c.native_token_sha256];
   } else {
    const fresh = c.stage === "verify_key" && h.job.key_mode === "new_key_attestation";
    const joint = `EXISTS(SELECT 1 FROM ${JOBS} WHERE ${own.predicate})`;
    if (fresh) statements.push(sql(`INSERT INTO ${COUNTERS}(key_ref_sha256,key_scope_sha256,counter,revision,last_claim)
     SELECT ?,?,0,1,? WHERE ${joint} AND NOT EXISTS(SELECT 1 FROM ${COUNTERS} WHERE key_ref_sha256=?)`,
     c.key_ref_sha256, h.job.key_scope_sha256, h.claim, ...own.bindings, c.key_ref_sha256));
    else statements.push(sql(`UPDATE ${COUNTERS} SET counter=?,revision=revision+1,last_claim=?
     WHERE key_ref_sha256=? AND key_scope_sha256=? AND revision=? AND counter<? AND revision<? AND ${joint}`,
     c.counter, h.claim, c.key_ref_sha256, h.job.key_scope_sha256, c.expected_counter_revision, c.counter, MAX, ...own.bindings));
    const marker = `EXISTS(SELECT 1 FROM ${COUNTERS} WHERE last_claim='${h.claim}')`;
    markers.push(marker); counterCondition = ` AND ${marker}`;
    setters = "key_ref_sha256=?"; values = [c.key_ref_sha256];
   }
   const phase = stages[h.stage][2];
   statements.push(sql(`UPDATE ${JOBS} SET ${setters},phase=?,revision=revision+1,active_claim=NULL,last_commit_claim=?
    WHERE ${own.predicate} AND revision<?${counterCondition}`, ...values, phase, h.claim, ...own.bindings, MAX));
   statements.push(sql(`UPDATE ${CLAIMS} SET outcome='committed' WHERE claim_id=? AND outcome='reserved' AND ${jobMarker(h.claim)}`, h.claim));
   statements.push(...atomic(h.claim, markers), final(h, phase, h.job.revision + 1));
   const result = await batch(statements, signal, h.job); guardJob(h.job, signal);
   return commitResult(result.at(-1)?.results[0] as Job | undefined);
  },
  async rejectOrRetireDataStage(reservation: DataReservation, reason: DataRetirement, signal?: AbortSignal): Promise<DataCommit> {
   const h = take(reservation, signal); if (!retirements.includes(reason)) invalid();
   retired.add(scope(h.job)); // Conservative local poison remains even after an unknown SQL result.
   const own = owned(h), statements = [sql(`UPDATE ${JOBS} SET phase=?,revision=revision+1,active_claim=NULL,last_commit_claim=?
    WHERE ${own.predicate} AND revision<?`, reason, h.claim, ...own.bindings, MAX),
    sql(`UPDATE ${CLAIMS} SET outcome='retired' WHERE claim_id=? AND outcome='reserved' AND ${jobMarker(h.claim)}`, h.claim)];
   statements.push(...atomic(h.claim, [jobMarker(h.claim), claimMarker(h.claim, "retired")]), final(h, reason, h.job.revision + 1));
   const result = await batch(statements, signal); guard(signal); return commitResult(result.at(-1)?.results[0] as Job | undefined);
  },
  async retireDataJob(input: { job_id: string; context_sha256: string }, reason: DataRetirement, signal?: AbortSignal): Promise<DataCommit> {
   guard(signal); const i = flat(input, ["job_id", "context_sha256"]); uuid(i.job_id); hash(i.context_sha256);
   if (!retirements.includes(reason)) invalid();
   retired.add(scope(i as { job_id: string; context_sha256: string }));
   const claim = privateClaim();
   const statements = [sql(`UPDATE ${JOBS} SET phase=?,revision=revision+1,active_claim=NULL,last_commit_claim=?
    WHERE job_id=? AND context_sha256=? AND data_epoch_sha256=? AND revision<?
    AND phase NOT IN ('REJECTED_RETIRED','WITHDRAWN_RETIRED','EXPIRED_RETIRED','UNCERTAIN_RETIRED')`,
    reason, claim, i.job_id, i.context_sha256, dataEpochSha256, MAX),
    sql(`UPDATE ${CLAIMS} SET outcome='retired' WHERE job_id=? AND outcome='reserved' AND ${jobMarker(claim)}`, i.job_id),
    ...atomic(claim, [jobMarker(claim), `(${jobMarker(claim)} AND NOT EXISTS(SELECT 1 FROM ${CLAIMS} c
     JOIN ${JOBS} j ON j.job_id=c.job_id WHERE j.last_commit_claim='${claim}' AND c.outcome='reserved'))`]),
    sql(`SELECT * FROM ${JOBS} WHERE job_id=? AND context_sha256=? AND data_epoch_sha256=? AND last_commit_claim=? AND phase=?`,
     i.job_id, i.context_sha256, dataEpochSha256, claim, reason)];
   const result = await batch(statements, signal); guard(signal); return commitResult(result.at(-1)?.results[0] as Job | undefined);
  },
 });
}
