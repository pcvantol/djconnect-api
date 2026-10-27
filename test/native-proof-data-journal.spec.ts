import { env } from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import schema from "../qualification/surface-push/native-proof-data-journal-schema.sql?raw";
import { createNativeProofDataJournal, type DataJobInput, type DataStage, type DataReservation, type DataCompletion } from "../src/surface-push/native-proof-data-journal";

// Disposable Worker/D1 DATA only. No native crypto, owner, clock, live provider or SDK.
const H = (n: number) => n.toString(16).padStart(64, "0");
const U = (n: number) => "00000000-0000-4000-8000-" + n.toString(16).padStart(12, "0");
const EPOCH = H(1), SCOPE = H(2), KEY = H(3), TRANSCRIPT = H(4), TARGET = H(5);
type Journal = ReturnType<typeof createNativeProofDataJournal>;
function job(n = 1): DataJobInput {
 return { job_id: U(n), bootstrap_binding_sha256: H(100 + n), context_sha256: H(200 + n), key_scope_sha256: SCOPE,
  key_operation_id: U(100 + n), target_operation_id: U(200 + n), key_nonce_sha256: H(300 + n), target_nonce_sha256: H(400 + n),
  bootstrap_deadline_unix_ms: 10000, original_grant_expires_at_unix_ms: 15000 };
}
function request(j: DataJobInput, stage: DataStage, revision: number) {
 const role = stage.endsWith("key") ? "key" : "target";
 return { job_id: j.job_id, context_sha256: j.context_sha256, stage, expected_revision: revision,
  operation_id: j[`${role}_operation_id`], nonce_sha256: j[`${role}_nonce_sha256`], body_sha256: H(9) };
}
async function row(j = job()) { return env.DB.prepare("SELECT * FROM native_proof_data_jobs WHERE job_id=?").bind(j.job_id).first<Record<string, any>>(); }
async function counter() { return env.DB.prepare("SELECT * FROM native_proof_data_key_counters WHERE key_ref_sha256=?").bind(KEY).first<Record<string, any>>(); }
const tables = ["native_proof_data_atomic_checks", "native_proof_data_claims", "native_proof_data_nonces", "native_proof_data_operations", "native_proof_data_key_counters", "native_proof_data_jobs"];
async function snapshot() {
 const rows = await env.DB.batch<Record<string, unknown>>(tables.map(t => env.DB.prepare(`SELECT * FROM ${t} ORDER BY 1,2`)));
 return rows.map(r => r.results);
}
async function prepareKey(api: Journal, j = job(), existing = false) {
 await api.createDataJob(j);
 const cap = await api.reserveDataStage(request(j, "prepare_key", 1));
 await api.completeDataStage(cap, existing
  ? { stage: "prepare_key", key_mode: "existing_key_assertion", key_ref_sha256: KEY, transcript_sha256: TRANSCRIPT }
  : { stage: "prepare_key", key_mode: "new_key_attestation", key_ref_sha256: null, transcript_sha256: TRANSCRIPT });
 return api.reserveDataStage(request(j, "verify_key", 3));
}
function verification(stage: "verify_key" | "verify_target", count = 0, rev: number | null = null): DataCompletion {
 return { stage, key_ref_sha256: KEY, transcript_sha256: stage === "verify_key" ? TRANSCRIPT : TARGET, counter: count, expected_counter_revision: rev };
}
async function verifiedKey(api: Journal, j = job()) { await api.completeDataStage(await prepareKey(api, j), verification("verify_key")); }
async function seedCounter() { await env.DB.prepare("INSERT INTO native_proof_data_key_counters VALUES(?,?,5,1,?)").bind(KEY, SCOPE, U(999)).run(); }
// Transport seam wraps an ACTUAL D1 session/batch, never mocks SQL results/atomicity.
function wrapped(hook: (submit: () => Promise<D1Result[]>) => Promise<D1Result[]>) {
 return new Proxy(env.DB, { get(target, key) {
  if (key === "withSession") return (first: string) => {
   expect(first).toBe("first-primary"); const session = target.withSession("first-primary");
   return new Proxy(session, { get(s, k) {
    if (k === "batch") return (statements: D1PreparedStatement[]) => hook(() => s.batch(statements));
    const v = Reflect.get(s, k); return typeof v === "function" ? v.bind(s) : v;
   } });
  };
  const v = Reflect.get(target, key); return typeof v === "function" ? v.bind(target) : v;
 } });
}

describe("uncomposed native-proof DATA journal, actual disposable Worker/D1", () => {
 beforeAll(async () => {
  for (const statement of schema.split(";").filter(s => s.replace(/--[^\n]*/g, "").trim())) await env.DB.prepare(statement).run();
 });
 beforeEach(async () => {
  await env.DB.prepare("DROP TRIGGER IF EXISTS data_test_partial").run();
  await env.DB.prepare("DROP TRIGGER IF EXISTS data_test_fail").run();
  await env.DB.batch(tables.map(t => env.DB.prepare(`DELETE FROM ${t}`)));
 });
 it("executes in actual Worker runtime and first-primary session; creates only DATA", async () => {
  expect(navigator.userAgent).toBe("Cloudflare-Workers");
  const api = createNativeProofDataJournal(env.DB, EPOCH), j = job();
  expect(await api.createDataJob(j)).toEqual({ classification: "DATA_ONLY_NOT_ADMISSION", job_id: j.job_id, phase: "APPROVED_AVAILABLE", revision: 1 });
  const r = await row(); expect(r).toMatchObject({ ...j, data_epoch_sha256: EPOCH, revision: 1 });
  expect(Object.keys(api).sort()).toEqual(["close", "completeDataStage", "createDataJob", "rejectOrRetireDataStage", "reserveDataStage", "retireDataJob"]);
 });
 it("traverses the original four phases with atomic global counter DATA and fixed deadlines", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), j = job(); await verifiedKey(api, j);
  expect(await row()).toMatchObject({ phase: "KEY_VERIFIED", revision: 5, key_ref_sha256: KEY });
  const cap = await api.reserveDataStage(request(j, "prepare_target", 5));
  await api.completeDataStage(cap, { stage: "prepare_target", transcript_sha256: TARGET, native_token_sha256: H(6) });
  const verify = await api.reserveDataStage(request(j, "verify_target", 7));
  expect(await api.completeDataStage(verify, verification("verify_target", 6, 1))).toMatchObject({ phase: "TARGET_VERIFIED", revision: 9 });
  expect(await counter()).toMatchObject({ counter: 6, revision: 2, key_scope_sha256: SCOPE });
  expect(await row()).toMatchObject({ bootstrap_deadline_unix_ms: j.bootstrap_deadline_unix_ms, original_grant_expires_at_unix_ms: j.original_grant_expires_at_unix_ms, key_transcript_sha256: TRANSCRIPT, target_transcript_sha256: TARGET, native_token_sha256: H(6), active_claim: null });
  const nonces = await env.DB.prepare("SELECT state FROM native_proof_data_nonces").all();
  expect(nonces.results).toEqual([{ state: "spent" }, { state: "spent" }]);
 });
 it("two adapters racing the same phase issue one opaque reservation and one complete result", async () => {
  const a = createNativeProofDataJournal(env.DB, EPOCH), b = createNativeProofDataJournal(env.DB, EPOCH); await a.createDataJob(job());
  const results = await Promise.allSettled([a.reserveDataStage(request(job(), "prepare_key", 1)), b.reserveDataStage(request(job(), "prepare_key", 1))]);
  expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1);
  const i = results.findIndex(r => r.status === "fulfilled"), won = results[i];
  if (won.status !== "fulfilled") throw new Error("missing actual winner");
  await (i === 0 ? a : b).completeDataStage(won.value, { stage: "prepare_key", key_mode: "new_key_attestation", key_ref_sha256: null, transcript_sha256: TRANSCRIPT });
  expect((await row())?.revision).toBe(3);
  expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM native_proof_data_claims").first("n")).toBe(1);
 });
 for (const field of ["key_operation_id", "target_operation_id", "key_nonce_sha256", "target_nonce_sha256"] as const) it(`rolls back cross-job/cross-role alias ${field}`, async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), one = job(), two = job(2); await api.createDataJob(one); const before = await snapshot();
  const alias = field.endsWith("operation_id") ? one.target_operation_id : one.target_nonce_sha256;
  await expect(api.createDataJob({ ...two, [field]: alias })).rejects.toThrow(); expect(await snapshot()).toEqual(before);
 });
 it("duplicate bootstrap or job cannot be reissued using fresh operation IDs", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); await api.createDataJob(job()); const before = await snapshot();
  await expect(api.createDataJob({ ...job(2), bootstrap_binding_sha256: job().bootstrap_binding_sha256 })).rejects.toThrow();
  await expect(api.createDataJob({ ...job(2), job_id: job().job_id })).rejects.toThrow(); expect(await snapshot()).toEqual(before);
 });
 for (const change of ["context", "epoch", "operation", "nonce", "revision", "stage"] as const) it(`foreign ${change} cannot reserve or modify a job`, async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); await api.createDataJob(job()); const before = await snapshot();
  const i = request(job(), "prepare_key", 1);
  if (change === "context") i.context_sha256 = H(90);
  if (change === "operation") i.operation_id = U(90);
  if (change === "nonce") i.nonce_sha256 = H(90);
  if (change === "revision") i.expected_revision = 2;
  if (change === "stage") i.stage = "prepare_target";
  const runner = change === "epoch" ? createNativeProofDataJournal(env.DB, H(90)) : api;
  await expect(runner.reserveDataStage(i)).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
 });
 it("counter zero-row CAS loss changes no job, claim or transcript (not a SQL exception)", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); await seedCounter(); const cap = await prepareKey(api, job(), true), before = await snapshot();
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 2))).rejects.toMatchObject({ code: "data_conflict" });
  expect(await snapshot()).toEqual(before);
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 1))).rejects.toMatchObject({ code: "reservation_spent_or_foreign" });
 });
 it("job zero-row CAS loss never advances counter, even though SQL batch has no error", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); await seedCounter(); const cap = await prepareKey(api, job(), true);
  await env.DB.prepare("UPDATE native_proof_data_jobs SET revision=revision+1 WHERE job_id=?").bind(job().job_id).run(); const before = await snapshot();
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 1))).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
 });
 it("two different jobs on the same key/counter revision produce only one counter winner", async () => {
  await seedCounter(); const a = createNativeProofDataJournal(env.DB, EPOCH), b = createNativeProofDataJournal(env.DB, EPOCH), one = job(), two = job(2);
  const ca = await prepareKey(a, one, true), cb = await prepareKey(b, two, true);
  const before = await snapshot();
  const results = await Promise.allSettled([a.completeDataStage(ca, verification("verify_key", 6, 1)), b.completeDataStage(cb, verification("verify_key", 7, 1))]);
  expect(results.filter(r => r.status === "fulfilled")).toHaveLength(1); expect((await counter())?.revision).toBe(2);
  const loser = results[0].status === "rejected" ? one : two;
  const after = await snapshot();
  expect(after[5].find(r => r.job_id === loser.job_id)).toEqual(before[5].find(r => r.job_id === loser.job_id));
  expect(after[1].filter(r => r.job_id === loser.job_id)).toEqual(before[1].filter(r => r.job_id === loser.job_id));
 });
 it("global same-key counter continues across principal data epochs without reset", async () => {
  const a = createNativeProofDataJournal(env.DB, EPOCH); await verifiedKey(a); const b = createNativeProofDataJournal(env.DB, H(999)), two = job(2);
  const cap = await prepareKey(b, two, true); await b.completeDataStage(cap, verification("verify_key", 8, 1));
  expect(await counter()).toMatchObject({ counter: 8, revision: 2 });
  const c = createNativeProofDataJournal(env.DB, H(998)), three = job(3); const newCap = await prepareKey(c, three);
  const before = await snapshot(); await expect(c.completeDataStage(newCap, verification("verify_key"))).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
 });
 it("foreign key scope cannot create a second/reset counter or advance the original", async () => {
  await seedCounter(); const api = createNativeProofDataJournal(env.DB, EPOCH), j = { ...job(), key_scope_sha256: H(99) };
  const cap = await prepareKey(api, j, true), before = await snapshot();
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 1))).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
 });
 for (const count of [0, 4, 5]) it(`equal or decreasing global counter ${count} leaves all rows unchanged`, async () => {
  await seedCounter(); const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api, job(), true), before = await snapshot();
  await expect(api.completeDataStage(cap, verification("verify_key", count, 1))).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
 });
 it("actual SQL invariant rolls back a counter update if a trigger then makes job CAS lose", async () => {
  await seedCounter(); const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api, job(), true), before = await snapshot();
  await env.DB.prepare(`CREATE TRIGGER data_test_partial AFTER UPDATE ON native_proof_data_key_counters BEGIN
   UPDATE native_proof_data_jobs SET revision=revision+1 WHERE job_id='${job().job_id}'; END`).run();
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 1))).rejects.toThrow(/CHECK constraint failed/);
  expect(await snapshot()).toEqual(before); // Trigger's own update is rolled back too.
 });
 it("actual SQL statement failure rolls back create and all earlier binding inserts", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), before = await snapshot();
  await env.DB.prepare("CREATE TRIGGER data_test_fail BEFORE INSERT ON native_proof_data_nonces BEGIN SELECT RAISE(ABORT,'fixture_sql_failure'); END").run();
  await expect(api.createDataJob(job())).rejects.toThrow(/fixture_sql_failure/); expect(await snapshot()).toEqual(before);
 });
 it("unexpected D1 exception is rethrown as identical original cause", async () => {
  const cause = new Error("synthetic_transport_failure"), db = wrapped(async () => { throw cause; });
  await expect(createNativeProofDataJournal(db, EPOCH).createDataJob(job())).rejects.toBe(cause);
 });
 for (const bad of ["wrong_transcript", "wrong_key", "extra_field", "stage", "counter", "revision"] as const) it(`consumes opaque completion before rejecting ${bad}`, async () => {
  await seedCounter(); const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api, job(), true), before = await snapshot();
  const c = verification("verify_key", 6, 1) as any;
  if (bad === "wrong_transcript") c.transcript_sha256 = H(99);
  if (bad === "wrong_key") c.key_ref_sha256 = H(99);
  if (bad === "extra_field") c.native_verified = true;
  if (bad === "stage") c.stage = "verify_target";
  if (bad === "counter") c.counter = 4294967296;
  if (bad === "revision") c.expected_counter_revision = Number.MAX_SAFE_INTEGER;
  await expect(api.completeDataStage(cap, c)).rejects.toMatchObject({ code: "invalid_data" });
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 1))).rejects.toMatchObject({ code: "reservation_spent_or_foreign" }); expect(await snapshot()).toEqual(before);
 });
 it("clones, forged caps and another instance cannot reconstruct a completion", async () => {
  const a = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(a), b = createNativeProofDataJournal(env.DB, EPOCH), before = await snapshot();
  expect(Object.isFrozen(cap)).toBe(true); expect(Object.keys(cap)).toEqual(["classification"]);
  for (const [runner, value] of [[a, { ...cap }], [b, cap], [a, {}]] as const) {
   await expect(runner.completeDataStage(value as DataReservation, verification("verify_key"))).rejects.toMatchObject({ code: "reservation_spent_or_foreign" });
  }
  expect(await snapshot()).toEqual(before); await a.completeDataStage(cap, verification("verify_key"));
 });
 for (const stop of ["close", "abort", "lost_reply"] as const) it(`postcommit ${stop} suppresses completion while actual counter/job commit remains`, async () => {
  let armed = false; const control = new AbortController(), cause = new Error("lost_data_reply"); let api: Journal;
  const db = wrapped(async submit => { const result = await submit(); if (armed) { if (stop === "close") api.close(); else if (stop === "abort") control.abort(); else throw cause; } return result; });
  api = createNativeProofDataJournal(db, EPOCH); const cap = await prepareKey(api); armed = true;
  const call = api.completeDataStage(cap, verification("verify_key"), control.signal);
  if (stop === "lost_reply") await expect(call).rejects.toBe(cause); else await expect(call).rejects.toMatchObject({ code: stop === "close" ? "journal_closed" : "operation_aborted" });
  expect(await counter()).toMatchObject({ counter: 0, revision: 1 }); expect(await row()).toMatchObject({ phase: "KEY_VERIFIED", revision: 5 });
  await expect(api.completeDataStage(cap, verification("verify_key"))).rejects.toMatchObject({ code: "reservation_spent_or_foreign" });
 });
 it("lost reservation reply cannot be recovered by restart or a new request UUID", async () => {
  let armed = false; const cause = new Error("lost_reservation"); const a = createNativeProofDataJournal(wrapped(async submit => { const r = await submit(); if (armed) throw cause; return r; }), EPOCH);
  await a.createDataJob(job()); armed = true; await expect(a.reserveDataStage(request(job(), "prepare_key", 1))).rejects.toBe(cause);
  const before = await snapshot(), b = createNativeProofDataJournal(env.DB, EPOCH);
  for (const input of [request(job(), "prepare_key", 1), request(job(), "prepare_key", 2), { ...request(job(), "prepare_key", 2), operation_id: U(777) }]) {
   await expect(b.reserveDataStage(input)).rejects.toMatchObject({ code: "data_conflict" });
  }
  expect(await snapshot()).toEqual(before);
 });
 for (const stop of ["close", "abort"] as const) it(`pre-submission ${stop} has no SQL effects and still spends a held cap`, async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api), before = await snapshot(), control = new AbortController();
  if (stop === "close") api.close(); else control.abort();
  await expect(api.completeDataStage(cap, verification("verify_key"), control.signal)).rejects.toMatchObject({ code: stop === "close" ? "journal_closed" : "operation_aborted" });
  await expect(api.completeDataStage(cap, verification("verify_key"))).rejects.toMatchObject({ code: "reservation_spent_or_foreign" }); expect(await snapshot()).toEqual(before);
 });
 it("retirement before completion preserves original binding and counter while retiring claim", async () => {
  await seedCounter(); const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api, job(), true), beforeCounter = await counter();
  await api.retireDataJob({ job_id: job().job_id, context_sha256: job().context_sha256 }, "WITHDRAWN_RETIRED"); const before = await snapshot();
  await expect(api.completeDataStage(cap, verification("verify_key", 6, 1))).rejects.toMatchObject({ code: "job_retired" });
  expect(await snapshot()).toEqual(before); expect(await counter()).toEqual(beforeCounter);
  expect(await env.DB.prepare("SELECT outcome FROM native_proof_data_claims WHERE stage='verify_key'").first("outcome")).toBe("retired");
 });
 it("retirement between reservation and submitted completion is enforced by SQL", async () => {
  let armed = false; const normal = createNativeProofDataJournal(env.DB, EPOCH);
  const api = createNativeProofDataJournal(wrapped(async submit => {
   if (armed) await normal.retireDataJob({ job_id: job().job_id, context_sha256: job().context_sha256 }, "EXPIRED_RETIRED");
   return submit();
  }), EPOCH);
  const cap = await prepareKey(api); armed = true;
  await expect(api.completeDataStage(cap, verification("verify_key"))).rejects.toMatchObject({ code: "data_conflict" });
  expect(await counter()).toBeNull(); expect((await row())?.phase).toBe("EXPIRED_RETIRED");
 });
 it("observed same-instance retirement after a submitted commit suppresses its result", async () => {
  let armed = false; let api: Journal;
  api = createNativeProofDataJournal(wrapped(async submit => {
   const r = await submit(); if (armed) { armed = false; await api.retireDataJob({ job_id: job().job_id, context_sha256: job().context_sha256 }, "WITHDRAWN_RETIRED"); }
   return r;
  }), EPOCH);
  const cap = await prepareKey(api); armed = true;
  await expect(api.completeDataStage(cap, verification("verify_key"))).rejects.toMatchObject({ code: "job_retired" });
  expect(await counter()).toMatchObject({ counter: 0, revision: 1 }); expect((await row())?.phase).toBe("WITHDRAWN_RETIRED");
 });
 it("retirement after commit retains counter truth and never retires a same-scope successor", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); await verifiedKey(api); await api.createDataJob(job(2)); const beforeCounter = await counter(), successor = await row(job(2));
  await api.retireDataJob({ job_id: job().job_id, context_sha256: job().context_sha256 }, "WITHDRAWN_RETIRED");
  expect(await counter()).toEqual(beforeCounter); expect(await row(job(2))).toEqual(successor);
 });
 it("wrong context or epoch cannot retire original job", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); await api.createDataJob(job()); const before = await snapshot();
  await expect(api.retireDataJob({ job_id: job().job_id, context_sha256: H(999) }, "WITHDRAWN_RETIRED")).rejects.toMatchObject({ code: "data_conflict" });
  await expect(createNativeProofDataJournal(env.DB, H(999)).retireDataJob({ job_id: job().job_id, context_sha256: job().context_sha256 }, "WITHDRAWN_RETIRED")).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
 });
 for (const reason of ["REJECTED_RETIRED", "WITHDRAWN_RETIRED", "EXPIRED_RETIRED", "UNCERTAIN_RETIRED"] as const) it(`once-only reserved-stage terminal DATA ${reason}`, async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api);
  expect(await api.rejectOrRetireDataStage(cap, reason)).toMatchObject({ classification: "DATA_ONLY_NOT_ADMISSION", phase: reason });
  expect(await counter()).toBeNull();
  await expect(api.rejectOrRetireDataStage(cap, reason)).rejects.toMatchObject({ code: "reservation_spent_or_foreign" });
 });
 for (const value of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN]) it(`invalid fixed deadline DATA ${value} has no effects`, async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), before = await snapshot();
  await expect(api.createDataJob({ ...job(), bootstrap_deadline_unix_ms: value })).rejects.toMatchObject({ code: "invalid_data" }); expect(await snapshot()).toEqual(before);
 });
 it("snapshots caller DATA before awaiting actual commit", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH), j = job(), original = { ...j }, promise = api.createDataJob(j);
  j.context_sha256 = H(999); j.bootstrap_deadline_unix_ms = 999999;
  await promise; expect(await row(original)).toMatchObject(original);
 });
 it("rejects accessors/inherited/extra fields without invoking their getter", async () => {
  const api = createNativeProofDataJournal(env.DB, EPOCH); let called = 0; const input = { ...job() };
  Object.defineProperty(input, "context_sha256", { enumerable: true, get() { called++; return H(999); } });
  await expect(api.createDataJob(input)).rejects.toMatchObject({ code: "invalid_data" }); expect(called).toBe(0);
  await expect(api.createDataJob(Object.assign(Object.create({ native_verified: true }), job()))).rejects.toMatchObject({ code: "invalid_data" });
  await expect(api.createDataJob({ ...job(), native_verified: true } as any)).rejects.toMatchObject({ code: "invalid_data" });
 });
 it("uint32 maximum advances once and safe revision exhaustion causes no partial writes", async () => {
  await seedCounter(); const api = createNativeProofDataJournal(env.DB, EPOCH), cap = await prepareKey(api, job(), true);
  await api.completeDataStage(cap, verification("verify_key", 4294967295, 1)); expect((await counter())?.counter).toBe(4294967295);
  const two = job(2); const next = await prepareKey(api, two, true), before = await snapshot();
  await expect(api.completeDataStage(next, verification("verify_key", 4294967295, 2))).rejects.toMatchObject({ code: "data_conflict" }); expect(await snapshot()).toEqual(before);
  await env.DB.prepare("UPDATE native_proof_data_jobs SET revision=? WHERE job_id=?").bind(Number.MAX_SAFE_INTEGER - 1, two.job_id).run(); const exhausted = await snapshot();
  await expect(api.reserveDataStage(request(two, "verify_key", Number.MAX_SAFE_INTEGER - 1))).rejects.toMatchObject({ code: "invalid_data" }); expect(await snapshot()).toEqual(exhausted);
 });
});
