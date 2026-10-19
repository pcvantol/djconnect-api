# Shared app-key API qualification, not native queue or key policy acceptance

Profile **0.4.0-draft / djc-rendezvous/1 NOT_FROZEN**. Existing sole API writer,
PR96, fresh ACK6270482702, parent b0a7f74/current main a4322fe unchanged.
This is TEST/EVIDENCE ONLY: no server/consumer runtime, endpoint, schema, key
policy, binding, configuration, dependency, workflow or deployment changes.
The NEW preQR exception review6269829702 is still open; no repeated review ask,
receiver activation, new writer, unchanged capture or crypto crossrun selected.

## Gap and actual execution

The earlier54handoff/126TV matrix used one software app-key perTV. It did not
prove one existing app-key's globally increasing assertion counter across several
TV contexts. `shared-key.check.mjs` now drives the actual private composedHTTP,
SQL/key routing/operation receipts and P256/JOSE path with ONE key per scenario.

[Final c full observations](workerd-shared-key-observations-v1.json):
**1208/1208 actual local workerd checks + isolated strict TypeScript + exit0 PASS**,
66executed source/input hashes match current bytes.1184existing regressions plus
24new shared-key scenarios. All24 assertion targets pass; that is22delivery
scenarios with58consumes, plus2expected finite no-delivery expiry scenarios, NOT
24successful handoffs. Existing54capacity targets/126fixtureTVconsumes remain
separately passing; original6preQR-reference cases remain separate too.

| New family | Scenarios | Delivered TV contexts | Meaning |
| --- | ---: | ---: | --- |
| Serial2/4TV, warm/cold, phases0/59000ms, approval30/115s |16 |48 |One appkey, monotone counter2/4, full sign→submit awaited before next |
| Lost registration201, exact2s/5s retries, recovery receipt then2TV |2 |4 |3registration attempts, recovercounter1, submitcounters2/3, same key expiry |
| Equal-counter fault / genuinely reordered software counters |2 |4 |401keeps pending context/keycounter, higher counter succeeds on SAME live challenge |
| Original keyday27/29 |2 |2 |Fresh120sTV, original key remains valid and recovery does not renew it |
| Keyday30equality / expiredTV |2 |0 |401for expiredkey; expiredTV old/higherproof and renewedchallenge all410 |

Every successfulTV has independent browser RSA key/claim/QR/context/JWE and one
actual consume/decrypt/context comparison; second consume409 and ciphertext
absent from live transaction state. Same appkey never merges TV authority. CrossTV
QR/transaction mix rejects before counter change. Key SQL expiry and counter are
read after operations. The out-of-order case generates softwarecounter1 then2,
delivers2 then1; the equal-counter case deliberately signs duplicate counters as
a SOFTWAREFAULT, not a claimed possible Applehardware sequence. After401, same
pendingTV/key state is compared unchanged. A fresh higher assertion on its same
still-valid original challenge succeeds without new key/QR/deadline.

The selected test loop awaits the FULL sign→submit sequence. Its maxoverlap1 is
fixture ordering, NOT evidence of an actual Apple/native per-key queue. No new
native retry authority is selected by the higher-counter API positive. Genuine
SDK errors and unsupported hardware/key cases still require owning native proof.

## Budget evidence and limits

All24observations await actual request-day/minute/IPpartition, allocation-day,
routed-key-call and creation-IP counters, with HMACidentity keys projected OUT.
Only bounded counts/timestamps/key status/counter/expiry/operation-group counts
are retained; no proofs, actual device IDs, claims, QR tokens or destinations.
Daily request counts are cumulative; retained minute rows can omit already
expired earlier minutes, especially phase59000+115s spanning THREEUTCminutes.
Do NOT sum retained rows and call that all offered traffic.

Concrete cold4TV/phase0/approval115s fixture:490admitted recognized requests across
two retained UTCminutes242/248. Poll232/224, native2/12, terminal0/12, create8/0;
4transaction allocations,1registration attempt,10routed key calls. Terminal12
includes4request/preflight pairs PLUS4deliberate second-consume409 probes. This is
an observed fixture, not provider throughput, cost, actualbrowsercache or an SLA.
Warm enrollment happens180s before the scenario and admission counters are reset;
those setup costs are explicitly EXCLUDED. Cold initial registration is INCLUDED.
Registration-loss cases explicitly charge initial+two identical retries (3), while
immutable recovery/submit receipt retries do not increment the keycounter again.

Private /2 admission256poll/16create/64native/16terminal, global10000/minute and
1000000/day with9000/900000regular ceilings,5allocations/IP-minute,500registration
attempts/day,50000keycalls/day,4challenge attempts/transaction and28/2/2proof slots
remain unchanged. This matrix does not newly saturate every slot/daily boundary;
prior component proofs retain their exact scopes. Busy503, terminal abuse, global
exhaustion, counter-order failure and original expiry can still stop a real flow.
No released2/4TVconcurrency, native queue, provider latency/load or daily capacity.

## Original lifetimes, native policy boundary and review corrections

Registration retries at2s/5s use exact original request/nonce/key and return the
original30day expiry. Recoverycounter1 plus identical receipt replay leaves1;
TVsubmit2/3 and identical submit receipts leave2/3. No key generation after error,
nonce/QRrenewal or expiry extension is introduced. EachTV keeps its own original
120s deadline independently of appkey/enrollment/recovery lifetimes.

Day27/29/30cases compare API response expiry to the actually stored original key
expiry. TheTV is created fresh on the tested day so it cannot expire before the
key test. Exactday30 key expiry yields generic401and logical revoked tombstone
with counter removed; it is not a changed counter/re-enrollment nor proof of
physical purge/backups/alarm execution. Originalday27/29 recovery returns the
same old absolute expiry. This proves SERVERAPI lifetime behavior, NOT a native
27day-renewal,24hcooldown/two-unresolved-handle/reinstallation policy. Those local
limits are not enforced as per-installation identity by this service and remain
existing Apple-owned integration evidence, not a new implementation assignment.

Independent readonly security and UX/privacy source/method reviews found noP1/P2.
Security requested actual budget snapshots, incorporated before final evidence;
review also clarified retained minute totals versus cumulative day. Native queue,
logical expiry and softwarecounter fault boundaries are explicit. Initial a1208
passed but lacked those new charge observations; b1208added counters/order detail;
final c1208also explicitly executes expired higher-counter/newchallenge410. None
is a runtime bugfix or a hidden failing run; c alone is the accepted final proof.
No runtime predicate or expected handoff weakened. Final independent evidence/doc
hash review receipts are recorded separately on API90/PR96; reviewers did not
execute workerd/provider/native acceptance themselves.

Runner requires EXACT66capacity+6preQR+24shared observations,96unique one-to-one
passed testcase/taskID/name receipts; missing/duplicate/partial evidence fails.
[Compact proof](workerd-shared-key-source-proof-v1.json) derives1208cases/66pins and
96observationhashes/full-proof binding from final c, NOT another execution.
Observation digest is UTF8 Python `json.dumps(observation, sort_keys=True,
separators=(",", ":"))`, no trailing newline. Existing offline1MiBJSON/2MiBblob
bounds remain; the full3.20MB proof is independently reviewed immutable evidence,
not read/parsed by the deployment preparation validator. Separate post-source
rebind can select this compact proof without changing22OPEN/null/false gates.
Old ff9ff57preparation stays consistent for unchanged older serverruntime; no
false rejection is claimed. API40/40,roottypes,107schema/two byte examples and
foundationprojectionPASS; protected exact-head CI receipts remain separate.

## Ownership and release

**LOCAL_SHARED_KEY_API_MATRIX_MET_NOT_NATIVE_OR_RELEASED**. APP-RECOVERY's local
API serialization/receipt/counter/expiry portion now has concrete evidence.
Actual supported Apple signqueue/restart/24h/twohandle/day27rotation and HA/device
composition remain owning native/installed evidence. Existing captures remain
delivered; no unchanged SDK/capture/key-generation loop is requested.

The only NEW receiver contract request remains preQR exception6269829702; this
same-key test delta creates no extra receiver ACK or schema change. API keeps
consolidation/corrections/exactrelease after actual required consumer decisions.
Public router/bindings/edge/WAF/provider/error taxonomy/load/cost/retention/logging/
artifact/security/deploymentauthorization and physical iPhone/HA/TV remain open.
No merge, Finalization, Cloudflarewrite, publicactivation, credentials, centralHA
fetch or B-screen/session rights. Timer remainsOFF; all other lane WIP preserved.

```sh
node qualification/rendezvous/run_shared_key_workerd.mjs /private/tmp/pinned-pki-deps /private/tmp/fresh-shared-output /private/tmp/pinned-jose-package
```

Existing pinned PKI/JOSE tools, isolated0700output/0600files; Worker egress and
telemetry disabled. ControlledDate and software enrollment/P256 are not actual
browser timing, genuine Appleattestation/provider behavior or HA/physicalTV proof.
