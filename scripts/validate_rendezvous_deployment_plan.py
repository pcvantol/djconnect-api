#!/usr/bin/env python3
"""Offline preparation consistency only. Never grants or performs deployment."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SUPPLYING_SHA = '896ccdc69447c231d04da3a6af4f27ea1f763697'

DELTA_PATH = 'docs/rendezvous/compatible-runtime-source-delta-v4.json'
DELTA_SHA256 = 'c5f23fd82f518310169f3a62945162d6625348cc128c54843b1f3d284af1926e'
DELTA_PROOFS = (('docs/rendezvous/compatible-runtime-shared-observations-v4.json',
  '5bee972aa2bc3a02fe44b8f92543a90d7f1d42791e4aed59490fc7ac855153e0',
  'source_sha256',
  66,
  'LOCAL_SHARED_APP_KEY_API_NOT_NATIVE_EDGE_OR_RELEASE_GO'),
 ('docs/rendezvous/compatible-runtime-product-observations-v3.json',
  '891d6687bc3807cef46bcd607dada422a1c0bbf8ac35ee46ae1cfa80d95c1446',
  'source_hashes',
  114,
  'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY'),
 ('docs/rendezvous/compatible-runtime-module-observations-v3.json',
  'd275f7f7eef0f6ff337bc8fccd05819965a8a8f742e7595363a5a4ad875694f8',
  'source_sha256',
  19,
  'INTERNAL_PRODUCT_MODULE_WITH_REAL_PRIVATE_DO_NOT_ROOT_HTTP_OR_EDGE_PROVENANCE'))
DELTA_SOURCES = frozenset(('package-lock.json', 'package.json', 'qualification/rendezvous/allocation-budget.ts', 'qualification/rendezvous/assertion-key-state.check.mjs', 'qualification/rendezvous/enrollment-evidence-candidate.mjs', 'qualification/rendezvous/enrollment-evidence.check.mjs', 'qualification/rendezvous/enrollment-key-state.check.mjs', 'qualification/rendezvous/provider-unavailable.check.mjs', 'qualification/rendezvous/request-admission.check.mjs', 'qualification/rendezvous/request-admission.ts', 'qualification/rendezvous/run_challenge_budget_workerd.mjs', 'qualification/rendezvous/run_shared_key_workerd.mjs', 'rendezvous-build-inputs.json', 'scripts/qualify_rendezvous_product_build.mjs', 'src/index.ts', 'src/rendezvous/composition.ts'))
DELTA_ADDITIONS = frozenset(('qualification/rendezvous/compatible-runtime-dependency-provenance-v3.json', 'src/surface-push/apns.ts', 'src/surface-push/composition.ts', 'src/surface-push/crypto.ts', 'src/surface-push/dispatch.ts', 'src/surface-push/handler.ts', 'src/surface-push/issuer-wire.ts', 'src/surface-push/issuer.ts', 'src/surface-push/provider.ts', 'src/surface-push/store.ts', 'src/surface-push/wire.ts'))
REFERENCE_DELTA = {'THIRD_PARTY_NOTICES.md': {'before': '6d6319ca3c47afc56d3d90a36533c97954c4f0e2f8234a15f179309b65be564e', 'after': '9809ddd902af8e05a2fe651476437aac6f2f54534774a4cc98e4afe798422c6f'}, 'docs/rendezvous/THIRD_PARTY_LICENSES_V1.md': {'before': 'd01864598df3730714db3065143f08cb6d21765f3323f0c8db20c7f5f9e60442', 'after': 'c1475aaa3964043219feb95d430bb53a7b8151e230e88c569cd3e72e07f36f0e'}}
INSTALLED_DEPENDENCY_DELTA = {'node_modules/@noble/hashes/_md.js': {'before': None, 'after': '60cf3010fda89e3e4d3f0e7ff1ce249e9c467f34b4fd41b6fd6101d9f69be763'}, 'node_modules/@noble/hashes/_u64.js': {'before': None, 'after': 'b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102'}, 'node_modules/@noble/hashes/esm/_md.js': {'before': 'cefb1557e7715cb2117c83f82ef3e3175c7e0391c80bd5795b2d4effc45fc582', 'after': None}, 'node_modules/@noble/hashes/esm/_u64.js': {'before': 'e48c0cfc10810439a4807b46db136ce603a3fa09b62584f513ef2f3ca496af54', 'after': None}, 'node_modules/@noble/hashes/esm/crypto.js': {'before': '9211d026c5d21e60e0126dd6f01150d87da5ba7261b8f468215c1264372ff5a5', 'after': None}, 'node_modules/@noble/hashes/esm/legacy.js': {'before': '4906186a82438392443e3ac2a59d0acbbec2bee2595d048c8d8c0dd6584d4bdb', 'after': None}, 'node_modules/@noble/hashes/esm/sha1.js': {'before': 'cd708647a4aad36d820253fc75e3a821efe842652b2c9134903c5aec33a2926a', 'after': None}, 'node_modules/@noble/hashes/esm/sha2.js': {'before': 'e729088b82e5450bff54c3a0013582aa42e1fe8f58dd31f5967f6ebe34c52299', 'after': None}, 'node_modules/@noble/hashes/esm/utils.js': {'before': '4cf4c1e05affedcb4fd584a43d76ae1a3711e34a36e2251b90c27e33ecc74fad', 'after': None}, 'node_modules/@noble/hashes/legacy.js': {'before': None, 'after': '690553a41af2fdd1e32ff6b534ba8508e95f1861c09c2d62fe762b6b501e09be'}, 'node_modules/@noble/hashes/sha2.js': {'before': None, 'after': '471746bba6ec4c6238ca41358d1d3b40b6ff31cf3363f0b4d550c649c1a8e83b'}, 'node_modules/@noble/hashes/utils.js': {'before': None, 'after': '037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c'}, 'node_modules/@peculiar/utils/build/_virtual/_rolldown/runtime.js': {'before': None, 'after': '1b10431e13b4eb349c329aba7d2beb6e6c224de569eac52966731c8239a941c9'}, 'node_modules/@peculiar/utils/build/bytes.js': {'before': None, 'after': '3257233f9027e4bd4db558cbe9dd29a1bece8395f5c699eabf04169e38b02779'}, 'node_modules/@peculiar/utils/build/bytes/buffer-source.js': {'before': None, 'after': 'd3a77cab2b8426ce297e8429b9d2ba03dbdbe97865b8173c51da0c92226b0f49'}, 'node_modules/@peculiar/utils/build/bytes/concat.js': {'before': None, 'after': '0d7017fef27635bed4dfed715736209bdf8e6959953549be15fc79cb103f8ea9'}, 'node_modules/@peculiar/utils/build/bytes/equal.js': {'before': None, 'after': '535bd6636af131a226dc59dd3642c4edb787611b71d78b94693b16523c5bd950'}, 'node_modules/@peculiar/utils/build/bytes/sequence.js': {'before': None, 'after': '771d13453aa579693ff8f1538ee754a8a21921bd910fe97bb571bddea572a4e1'}, 'node_modules/@peculiar/utils/build/converters/convert.js': {'before': None, 'after': '86c63126f664051c739c52945ce076a4aeb1171da95ddf78dba7d95886b80a8c'}, 'node_modules/@peculiar/utils/build/converters/defaults.js': {'before': None, 'after': '1781d65e5ebe30b2340b023bbcfff40fb9cee2e70918ce7e7f0c84999bd2fd7e'}, 'node_modules/@peculiar/utils/build/converters/registry.js': {'before': None, 'after': '162d1ba3bdbc3d014a9c48bd8c5aa325f5eb8a958104c7fe03d7ea8ef1319b40'}, 'node_modules/@peculiar/utils/build/encoding/base64.js': {'before': None, 'after': '98b0130b60565fcadfed4aa50b8854de6eafe9c224dbd2c5c994c673a50066c4'}, 'node_modules/@peculiar/utils/build/encoding/base64url.js': {'before': None, 'after': 'a2131390bb30cce0d6ab42ff32e056f7d665552449cb1829787a3001fae9add1'}, 'node_modules/@peculiar/utils/build/encoding/binary.js': {'before': None, 'after': '92727e40c10bb92f0bcf9b8841590ef11df1764b3027be3041e44f04edf56794'}, 'node_modules/@peculiar/utils/build/encoding/hex.js': {'before': None, 'after': 'a7066c019c44348f1d1fa6bb1972bf368a304af41b04e2dff3e4805a5cef81e0'}, 'node_modules/@peculiar/utils/build/encoding/utf16.js': {'before': None, 'after': '20ce0b98604a618599e5831158f94a032f94aa0a50c0e280dea776656a7f166c'}, 'node_modules/@peculiar/utils/build/encoding/utf8.js': {'before': None, 'after': 'd0e538af363ad2c92b6578f62902d6a374e94b34c7e90a9f5261743642c7c8a5'}, 'node_modules/@peculiar/utils/build/index.js': {'before': None, 'after': '249fb0a4cf5b6dd1cbc12f2c109d9ad5afa55fc34f6696db8a971b09efc6ad36'}, 'node_modules/@peculiar/utils/build/integer/int.js': {'before': None, 'after': '0b2523f5a56762ebc749a77ecd9f8ad1914d1240300efffd7ac87926b27c31b5'}, 'node_modules/@peculiar/utils/build/integer/uint.js': {'before': None, 'after': '53609f035e2e0513d1321147b5dbb8cf8ce483cd0fa3023e61a70dd1e0f85bab'}, 'node_modules/@peculiar/utils/build/legacy/buffer-source-converter.js': {'before': None, 'after': '61261697f592eefdda6393751447b22db37708d8cef7b42ecb79e69c366c2a67'}, 'node_modules/@peculiar/utils/build/legacy/convert.js': {'before': None, 'after': 'd604e5ffd876889bb177cf9ec2ebef468bc165ac7ffe28d2ab87736cc4263a6f'}, 'node_modules/@peculiar/utils/build/legacy/functions.js': {'before': None, 'after': 'be5e4255b7b45de3415b35f136656f3e44a413577740622a90ecea8b32e02b5f'}, 'node_modules/@peculiar/utils/build/pem/pem.js': {'before': None, 'after': '4204fe9f301df4cb96ed08ededb41934ec33e784d3aab1a31af3b9867184520b'}, 'node_modules/asn1js/build/index.es.js': {'before': 'ee1dbac2b2f8bc0edd15f56932d847f5a8565b20d0b2b22d6c978360279899e4', 'after': None}, 'node_modules/asn1js/build/index.js': {'before': None, 'after': '4a3cfe45a598edb62cbfcf89426f6a2556dd505bf3838935c106829fbfe32024'}, 'node_modules/bytestreamjs/build/bit.js': {'before': None, 'after': 'a3b2c1f5f923a1ed39b55745a4e501b2b6092b081c380acc73a542456e6687f9'}, 'node_modules/bytestreamjs/build/bit_stream.js': {'before': None, 'after': '220bc62673ddcbd43073d2f1f056c3da3ed6a4f44dc183af569b2e7a876ecca4'}, 'node_modules/bytestreamjs/build/byte_stream.js': {'before': None, 'after': '1dec0f7089d75334e9b58ae9b4690879dd88043cd3f377e9af4b20f9f0ff1b39'}, 'node_modules/bytestreamjs/build/helpers.js': {'before': None, 'after': '0e8003c7739767109d5a4931dde4c3aedec18100b5a3e3bc327d560cb6ef606c'}, 'node_modules/bytestreamjs/build/index.js': {'before': None, 'after': '4794bc465f13842696ec8c1ad027de9c198ad55c3c482059fe1694204833ebc2'}, 'node_modules/bytestreamjs/build/mjs/bit.js': {'before': '948aa3449ba484a4b33b8d251714a655ec67544e991902cd1773cab0c8cc1bfe', 'after': None}, 'node_modules/bytestreamjs/build/mjs/bit_stream.js': {'before': '109291e1cfc9e95db75748154cffd39163145d66fd85a6240d28eb5d8335c2f8', 'after': None}, 'node_modules/bytestreamjs/build/mjs/byte_stream.js': {'before': 'd265091e6b5209c1839b2c3f4d91df681a37bb1d3e3834891619d422277b634c', 'after': None}, 'node_modules/bytestreamjs/build/mjs/helpers.js': {'before': '9fe919254ac3db6db045e008cce021c5223146d8d9fbb2b3c5aa45a9ec1b2abf', 'after': None}, 'node_modules/bytestreamjs/build/mjs/index.js': {'before': '3139b1bdc36c99c155d14ff24e46ae5f3ecf78900f56de49bd466da2ed022de1', 'after': None}, 'node_modules/bytestreamjs/build/mjs/seq_bit_stream.js': {'before': '01b075ad7bc1c49fa2854cbe3c82407c29f12d01a926e0e77c68fe266159e5f8', 'after': None}, 'node_modules/bytestreamjs/build/mjs/seq_stream.js': {'before': 'bfa20e5092a8b5387091c9b00133a0fcaedf8bff090840cbb3872045346c1dc4', 'after': None}, 'node_modules/bytestreamjs/build/seq_bit_stream.js': {'before': None, 'after': '656eb46b51688d11ca3eb6b673e5d9f7c837727378676447da564b9a9416518e'}, 'node_modules/bytestreamjs/build/seq_stream.js': {'before': None, 'after': '6d5446062668db78d3ca06dbf75f5a76544347a93781af69c458f6448b17a6b4'}, 'node_modules/pkijs/build/index.es.js': {'before': '5f5c08540929f01ee75373b9f317753aeb6a7239241658473bb37826e2f85a50', 'after': None}, 'node_modules/pkijs/build/index.js': {'before': None, 'after': '81323b7ffbe635d9fbfeef6cb6db6166c8c1a9ff6e4b1158a4c09515ab8c1685'}, 'node_modules/pvtsutils/build/index.js': {'before': '8cf4300225298c7811fd72840f84ebd12dda5359f29fffdba09cb67a63a5943f', 'after': None}, 'node_modules/pvutils/build/utils.es.js': {'before': 'e1a942c322462a4a2b1a2311b2b40bd9ab1779273d98fca085e074532f96db98', 'after': None}}
SOURCE_PROVENANCE = {'baseline_sha': '896ccdc69447c231d04da3a6af4f27ea1f763697', 'delta_sha256': 'c5f23fd82f518310169f3a62945162d6625348cc128c54843b1f3d284af1926e', 'effective_source_map_sha256': '1579fae6ad1e03907c747516883e7aeef68404026501170e090b8bca0bc53b24', 'kind': 'BASELINE_PLUS_PINNED_DELTA'}

PROOFS = (('docs/rendezvous/assertion-crypto-shared-observations-v1.json',
  'd1b5d6bdc6a2009c31ba96ce2af1833c69b3794420fa6d0096103f2911701a4b',
  'source_sha256',
  66,
  'LOCAL_SHARED_APP_KEY_API_NOT_NATIVE_EDGE_OR_RELEASE_GO'),
 ('docs/rendezvous/sharp-0355-composition-observations-v1.json',
  'd0ef8018d7b494e27667ef9915c68a9849754b36d944f2cddf3ae910092ed531',
  'source_sha256',
  19,
  'INTERNAL_PRODUCT_MODULE_WITH_REAL_PRIVATE_DO_NOT_ROOT_HTTP_OR_EDGE_PROVENANCE'),
 ('docs/rendezvous/sharp-0355-build-observations-v1.json',
  'cd0c1df612e1218edc1483c9f04d6166d40680652ff463105f84446de99a5089',
  'source_hashes',
  85,
  'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY'))

REFERENCES = ('wrangler.jsonc', '.github/workflows/deploy-api-worker.yml',
              '.github/workflows/api-release-artifact.yml',
              'docs/rendezvous/implementation-contract-release-v1.json',
              'LICENSE', 'THIRD_PARTY_NOTICES.md',
              'docs/rendezvous/THIRD_PARTY_LICENSES_V1.md',
              *(proof[0] for proof in PROOFS))
PROPOSED_CONFIGURATION = {
    'COMPOSED_POLICY_ENABLED': 'djc-http-composition-qualification/1',
    'REQUEST_POLICY_ENABLED': 'djc-request-admission-qualification/2',
    'ALLOCATION_POLICY_ENABLED': 'djc-allocation-qualification/1',
    'INDEX_POLICY_ENABLED': 'djc-index-qualification/1',
    'ASSERTION_POLICY_ENABLED': 'ios-dev-qualification/1',
    'ASSERTION_POLICY_EXPIRES_AT': None,
    'ENROLLMENT_POLICY_REVISION': None,
    'RENDEZVOUS_EDGE_POLICY': 'djc-direct-edge-identity/1-candidate',
}
BINDINGS = {
    'REQUEST_ADMISSION': 'RequestAdmission',
    'ADMISSION_STATE': 'AllocationBudget',
    'ALLOCATION_INDEX': 'AllocationIndex',
    'ENROLLMENT_COORDINATOR': 'EnrollmentCoordinator',
    'COMPOSED_TRANSACTIONS': 'BudgetedTransactionCoordinator',
}
GATES = ('joint_contract_freeze', 'independent_full_protocol_security',
         'public_entrypoint_and_all_gated_paths', 'trusted_cf_ip_provenance',
         'edge_waf_rejected_traffic_spend', 'account_plan_and_shared_usage',
         'namespace_and_migration_collision', 'provider_status_and_error_taxonomy',
         'genuine_supported_signed_ios', 'ha_external_route_and_display_admission',
         'physical_iphone_ha_tv', 'load_latency_cpu_sql_duration',
         'approved_spend_and_capacity', 'platform_logs_retention_backups_dpa',
         'secret_presence_and_rotation', 'cleanup_alerts_and_physical_retention',
         'immutable_product_artifact', 'protected_main_and_separate_finalization',
         'applicable_central_manifest', 'exact_deployment_authorization',
         'compatible_rollback_readback', 'authorized_live_smoke')
SUCCESS = 'PREPARATION_CONSISTENT_BLOCKED_NOT_AUTHORIZED'


def require(value):
    if not value:
        raise ValueError('invalid_preparation')


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def decode(raw):
    require(len(raw) <= 1024 * 1024)
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json')))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(name):
    # Paths are pinned constants or come from the independently pinned proof.
    safe_path(name)
    environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    environment.update(GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0',
                       GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1')
    result = subprocess.run(['git', 'cat-file', 'blob', SUPPLYING_SHA + ':' + name],
                            cwd=ROOT, capture_output=True, timeout=10, check=True,
                            env=environment)
    require(len(result.stdout) <= 2 * 1024 * 1024)
    return result.stdout


def safe_path(name):
    require(isinstance(name, str) and name and '\\' not in name)
    parts = name.split('/')
    require(all(part not in ('', '.', '..') for part in parts))
    current = ROOT
    for part in parts:
        current = current / part
        require(not current.is_symlink())
    require(current.resolve().is_relative_to(ROOT))
    return current


def merge_sources(shared, module, root, *, with_closed_issuer=False):
    """Only immutable proof maps define inputs; never discover mutable Git state."""
    sources = {}
    excluded = set()
    for index, recorded in enumerate((shared, module, root)):
        require(isinstance(recorded, dict) and len(recorded) == (66, 19, 114 if with_closed_issuer else 85)[index])
        for name, expected in recorded.items():
            require(isinstance(name, str) and isinstance(expected, str)
                    and len(expected) == 64 and all(c in '0123456789abcdef' for c in expected))
            path = (name if name.startswith(('docs/', 'src/'))
                    else 'qualification/rendezvous/' + name) if index == 0 else name
            if index == 2 and path.startswith('node_modules/'):
                require('\\' not in path and all(p not in ('', '.', '..') for p in path.split('/')))
                excluded.add(path)
                continue  # Installed package bytes are not immutable Git blobs.
            safe_path(path)
            require(path not in sources or sources[path] == expected)
            sources[path] = expected
    require(len(excluded) == (50 if with_closed_issuer else 32) and len(sources) == (117 if with_closed_issuer else 106))
    return sources


def immutable_baseline():
    maps = []
    for name, pin, field, count, scope in PROOFS:
        raw = blob(name)
        require(digest(raw) == pin)
        proof = decode(raw)
        require(proof['scope'] == scope and isinstance(proof[field], dict) and len(proof[field]) == count)
        maps.append(proof[field])
    sources = merge_sources(*maps)
    for path, expected in sources.items():
        require(digest(blob(path)) == expected)
    return sources, {name: digest(blob(name)) for name in REFERENCES}


def source_map_digest(sources):
    return digest(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode('utf-8'))


def pinned_working_proof(name, pin):
    path = safe_path(name)
    require(path.is_file())
    raw = path.read_bytes()
    require(digest(raw) == pin)
    return decode(raw)


def baseline():
    # Original protected history remains authoritative, even after squash deletes PR refs.
    original, references = immutable_baseline()
    delta = pinned_working_proof(DELTA_PATH, DELTA_SHA256)
    require(isinstance(delta, dict) and set(delta) == {'schema_version', 'scope',
        'baseline_source_sha', 'baseline_source_map_sha256',
        'effective_source_map_sha256', 'changes', 'proofs'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
        and delta['scope'] == 'EXACT_SOURCE_DELTA_NOT_DEPLOYMENT_AUTHORIZATION'
        and delta['baseline_source_sha'] == SUPPLYING_SHA
        and delta['baseline_source_map_sha256'] == source_map_digest(original))
    changes = delta['changes']
    require(isinstance(changes, dict) and set(changes) == DELTA_SOURCES | DELTA_ADDITIONS)
    effective = dict(original)
    for name, change in changes.items():
        safe_path(name)
        require(isinstance(change, dict) and set(change) == {'before', 'after'}
            and ((name in DELTA_ADDITIONS and name not in original and change['before'] is None)
                 or (name in DELTA_SOURCES and change['before'] == original[name]))
            and change['after'] != change['before']
            and isinstance(change['after'], str) and len(change['after']) == 64
            and all(c in '0123456789abcdef' for c in change['after']))
        effective[name] = change['after']
    require(delta['effective_source_map_sha256'] == source_map_digest(effective)
        == SOURCE_PROVENANCE['effective_source_map_sha256'])
    require(delta['proofs'] == {key: {'path': record[0], 'sha256': record[1]}
        for key, record in zip(('shared', 'root', 'module'), DELTA_PROOFS)})
    fresh = []
    for name, pin, field, count, scope in DELTA_PROOFS:
        proof = pinned_working_proof(name, pin)
        require(proof['scope'] == scope and isinstance(proof[field], dict)
            and len(proof[field]) == count)
        fresh.append(proof[field])
        references[name] = pin
    old_root = decode(blob(PROOFS[2][0]))[PROOFS[2][2]]
    installed = lambda values: {key: value for key, value in values.items()
                              if key.startswith('node_modules/')}
    expected_installed = dict(installed(old_root))
    # Explicit reviewed v4 add/remove/change paths; immutable original32 remain checked.
    require(set(INSTALLED_DEPENDENCY_DELTA) == {'node_modules/@noble/hashes/esm/legacy.js', 'node_modules/@peculiar/utils/build/encoding/base64.js', 'node_modules/@peculiar/utils/build/legacy/convert.js', 'node_modules/asn1js/build/index.js', 'node_modules/bytestreamjs/build/bit.js', 'node_modules/@noble/hashes/esm/utils.js', 'node_modules/@peculiar/utils/build/bytes.js', 'node_modules/pkijs/build/index.js', 'node_modules/bytestreamjs/build/index.js', 'node_modules/@noble/hashes/esm/_md.js', 'node_modules/@peculiar/utils/build/converters/registry.js', 'node_modules/@peculiar/utils/build/integer/uint.js', 'node_modules/bytestreamjs/build/mjs/bit.js', 'node_modules/@noble/hashes/utils.js', 'node_modules/@peculiar/utils/build/bytes/equal.js', 'node_modules/bytestreamjs/build/mjs/index.js', 'node_modules/bytestreamjs/build/bit_stream.js', 'node_modules/@noble/hashes/_u64.js', 'node_modules/@peculiar/utils/build/integer/int.js', 'node_modules/@peculiar/utils/build/encoding/base64url.js', 'node_modules/pkijs/build/index.es.js', 'node_modules/bytestreamjs/build/byte_stream.js', 'node_modules/@peculiar/utils/build/legacy/buffer-source-converter.js', 'node_modules/@noble/hashes/esm/sha2.js', 'node_modules/bytestreamjs/build/mjs/bit_stream.js', 'node_modules/bytestreamjs/build/mjs/byte_stream.js', 'node_modules/bytestreamjs/build/mjs/helpers.js', 'node_modules/@peculiar/utils/build/encoding/utf8.js', 'node_modules/asn1js/build/index.es.js', 'node_modules/@peculiar/utils/build/index.js', 'node_modules/@noble/hashes/sha2.js', 'node_modules/@peculiar/utils/build/bytes/concat.js', 'node_modules/@peculiar/utils/build/converters/defaults.js', 'node_modules/@peculiar/utils/build/encoding/utf16.js', 'node_modules/@noble/hashes/_md.js', 'node_modules/@peculiar/utils/build/pem/pem.js', 'node_modules/bytestreamjs/build/mjs/seq_stream.js', 'node_modules/bytestreamjs/build/seq_bit_stream.js', 'node_modules/pvutils/build/utils.es.js', 'node_modules/@peculiar/utils/build/bytes/sequence.js', 'node_modules/@noble/hashes/esm/_u64.js', 'node_modules/bytestreamjs/build/seq_stream.js', 'node_modules/@noble/hashes/esm/crypto.js', 'node_modules/@peculiar/utils/build/bytes/buffer-source.js', 'node_modules/bytestreamjs/build/mjs/seq_bit_stream.js', 'node_modules/@noble/hashes/legacy.js', 'node_modules/bytestreamjs/build/helpers.js', 'node_modules/@noble/hashes/esm/sha1.js', 'node_modules/@peculiar/utils/build/encoding/binary.js', 'node_modules/pvtsutils/build/index.js', 'node_modules/@peculiar/utils/build/encoding/hex.js', 'node_modules/@peculiar/utils/build/converters/convert.js', 'node_modules/@peculiar/utils/build/legacy/functions.js', 'node_modules/@peculiar/utils/build/_virtual/_rolldown/runtime.js'})
    for name, change in INSTALLED_DEPENDENCY_DELTA.items():
        require(set(change) == {'before', 'after'}
            and expected_installed.get(name) == change['before']
            and (name in expected_installed) == (change['before'] is not None)
            and change['before'] != change['after'])
        for value in change.values():
            require(value is None or isinstance(value, str) and len(value) == 64
                and all(c in '0123456789abcdef' for c in value))
        if change['after'] is None:
            require(name in expected_installed)
            del expected_installed[name]
        else:
            expected_installed[name] = change['after']
    require(installed(fresh[1]) == expected_installed)
    require(merge_sources(fresh[0], fresh[2], fresh[1], with_closed_issuer=True) == effective)
    # Version-label updates retain the unchanged license texts, with exact supplier fences.
    require(set(REFERENCE_DELTA) == {'THIRD_PARTY_NOTICES.md', 'docs/rendezvous/THIRD_PARTY_LICENSES_V1.md'})
    for name, change in REFERENCE_DELTA.items():
        require(set(change) == {'before', 'after'} and references.get(name) == change['before']
            and change['before'] != change['after'] and isinstance(change['after'], str)
            and len(change['after']) == 64 and all(c in '0123456789abcdef' for c in change['after']))
        references[name] = change['after']
    references[DELTA_PATH] = DELTA_SHA256
    return effective, references


def validate(plan):
    expected = {'schema_version', 'kind', 'status', 'supplying_source_sha', 'source_provenance',
                'profile', 'wire', 'worker', 'service_origin', 'browser_origin',
                'compatibility_date', 'activation_allowed', 'public_entrypoint',
                'central_manifest_id', 'artifact_id', 'artifact_sha256', 'approval',
                'account_id', 'account_plan', 'bindings', 'migration', 'secret_names',
                'gates', 'source_hashes', 'reference_hashes', 'proposed_configuration'}
    require(isinstance(plan, dict) and set(plan) == expected)
    constants = {'schema_version': 1, 'kind': 'rendezvous_deployment_preparation',
                 'status': 'NOT_AUTHORIZED', 'supplying_source_sha': SUPPLYING_SHA,
                 'profile': '0.4.0-draft', 'wire': 'djc-rendezvous/1',
                 'worker': 'djconnect-api', 'service_origin': 'https://api.djconnect.dev',
                 'browser_origin': 'https://vibecast.tv', 'compatibility_date': '2026-06-20'}
    for key, value in constants.items():
        require(type(plan[key]) is type(value) and plan[key] == value)
    require(plan['source_provenance'] == SOURCE_PROVENANCE)
    require(plan['activation_allowed'] is False)
    for key in ('public_entrypoint', 'central_manifest_id', 'artifact_id',
                'artifact_sha256', 'approval', 'account_id', 'account_plan'):
        require(plan[key] is None)
    require(plan['bindings'] == BINDINGS)
    require(plan['migration'] == {'proposed_tag': 'djc-rendezvous-sqlite-v1',
                                 'status': 'PROPOSED_COLLISION_UNVERIFIED',
                                 'new_sqlite_classes': sorted(BINDINGS.values())})
    require(plan['secret_names'] == ['RENDEZVOUS_IP_HASH_KEY', 'RECEIPT_ACTIVE_KEY',
                                     'RECEIPT_PREVIOUS_KEY'])
    require(plan['proposed_configuration'] == PROPOSED_CONFIGURATION)
    require(plan['gates'] == {name: 'OPEN' for name in GATES})
    sources, references = baseline()
    require(plan['source_hashes'] == sources and plan['reference_hashes'] == references)
    for path, expected_hash in {**sources, **references}.items():
        require(digest(safe_path(path).read_bytes()) == expected_hash)
    return {'status': SUCCESS, 'activation_allowed': False,
            'supplying_source_sha': SUPPLYING_SHA, 'source_provenance': SOURCE_PROVENANCE,
            'open_gate_count': len(GATES)}


def main():
    # No execute/deploy/approve mode. This output cannot be a dispatch receipt.
    try:
        require(len(sys.argv) == 1)
        raw = safe_path('docs/rendezvous/deployment-preparation-v1.json').read_bytes()
        result = validate(decode(raw))
    except Exception:
        print(json.dumps({'status': 'PREPARATION_INVALID_NOT_AUTHORIZED',
                          'activation_allowed': False}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
