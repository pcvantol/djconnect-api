# Closed installation-principal DATA codec

This standalone library implements the personally reviewed private R2 DATA
record/codec design `7b44758c5f7bba76dd3f61b042a776330ee25697523d3bd05248a5697f76db4b`.
Its bounded design closure is
`924a049efe44d129f9b8feda13f1715e942aec92f90b162adde947632ded1045`.
This implementation requires its own whole-source/exact review and delivery.
It is developed from reviewed parent PR168 candidate
`b6e5360f05ffff3107c7c5f4256f9e1898ee329d`, normally merged with its own human
approval as protected main `bd746b0602926720a57b518907b60c66289fcc14`.
Those parent commits have identical trees. This child is restacked onto that
protected main; the separate parent Final and this source's own exact review,
CI, merge decision and original delivery remain distinct gates.

`decodeRecord(text, recordType)` accepts exactly eleven closed record families
and a separate closed operation-status envelope with six outcome variants.
`decodeTranscript(text)` preserves the exact private R1 public byte schema,
body digest and fixed-domain signing-input digest. It does **not** verify a
signature or import/check a public point on the curve. The separate possession
crypto owner must do that; no caller receives a signer or authority handle here.
Every successful result is `INSTALLATION_PRINCIPAL_DATA_ONLY`.

Only primitive canonical JSON text enters decoding. A bounded lexical gate runs
before the strict duplicate-key parser: outer ASCII UTF8 <=32768bytes, depth<=4,
<=256 tokens; separately scanned embedded R1 <=4096bytes, depth<=4, <=128 tokens.
String escapes are lexed as strings; canonical equality rejects aliases, BOM,
extra whitespace, trailing LF, duplicate keys and noncanonical numbers. Public
JWK coordinates require exact encoding and a recomputed pin, without private or
extra members. Integer, kind, version and field sets are closed. Crypto digest
failures retain their original cause; malformed data has a bounded own error.

The primitive chain helpers relate original generation preparation, public
custody receipt, separately proposed installation subject/epoch, original
admission context, proof preparation and the separately supplied original R1
body. They require full original relationships, not just a matching key. Caller
objects are copied into owned primitive snapshots before awaits; accessors and
extra fields reject. Outputs and nested public records are frozen.

The original-operation withdrawal DATA variant targets an exact acknowledged
intent/subject/registration/challenge and never requires a future principal
result hash or caller knowledge of its current revision. Known-result withdrawal
is a separate closed family. Tombstone/principal/devicejoin helpers only compare
claimed public records. They execute no SQL, intent reservation, nonce consumption,
CAS, retirement, clock check, operator/install authentication or live withdrawal.
Core generation/signing journals and the API registry are separate transaction
domains; matching metadata proves no distributed atomicity or actual effect.
The existing pair-bound registry V1, af201/090b/Source153 and ordinary Worker
routes, bindings and production factories are unchanged.

The frozen Core fixture is copied byte-for-byte from protected Final1386
`351e5870946c0ac020ec01137fdb14a90960a827`:
`5a5eb360c21aaf8da7f7883c4bd9c1e6b05f4d9e62d149eaec25b39045470153`.
It contains expired2024, explicitly synthetic labels and public P-256 G, never
actual installation/key/authority evidence. The shared14 mutation bytes come
from the independent Node/Core reference check
`7930f243933bc0efa846878ac2d0d3fdc45b93bb8df4a1dd551065d9d7ed98cb`.
The47 original stateful design expectations remain declarative with0 executions;
codec tests do not qualify a registry, provider, signer or native product.

Dedicated strict types, actual workerd tests and an actual packaged-ESM host
check qualify this new source. The source packager verifies tracked input pins
and installed esbuild hashes, emits a standalone ESM plus schema/design/fixture,
and asserts its exact three-input graph. It generates no Worker configuration,
cloud resources, keys, signing effects, HTTP routes or admission factory.

Local source qualification:67 actual workerd cases PASS,0 FAIL,0 SKIP;
dedicated and root strict types PASS. The existing root API index suite has
40 PASS,0 FAIL,0 SKIP. The delivered standalone ESM host check covers all11
record families,6 status variants and6 primitive chain helpers. These results
do not execute the47 stateful design expectations or establish live authority.
