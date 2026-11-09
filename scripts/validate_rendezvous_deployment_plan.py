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

DELTA_PATH = 'docs/rendezvous/closed-enrollment-service-source-delta-v2.json'
DELTA_SHA256 = '8353b2c06755d12ea08c304d6ddb4b691863ee0a774fc314bd95a938d85407e5'
DELTA_PROOFS = (('docs/rendezvous/compatible-runtime-shared-observations-v4.json',
  '5bee972aa2bc3a02fe44b8f92543a90d7f1d42791e4aed59490fc7ac855153e0',
  'source_sha256',
  66,
  'LOCAL_SHARED_APP_KEY_API_NOT_NATIVE_EDGE_OR_RELEASE_GO'),
 ('docs/rendezvous/closed-enrollment-service-product-observations-v2.json',
  '82b0084e162f8ba73669b8a634884bd4a26e2d9ba1263191e1af26b5c9433c15',
  'source_hashes',
  116,
  'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY'),
 ('docs/rendezvous/compatible-runtime-module-observations-v4.json',
  '5389556e1ee2ee1e1f1d90af1ac17f3346157121f21df4e031ed23011c9f69b6',
  'source_sha256',
  19,
  'INTERNAL_PRODUCT_MODULE_WITH_REAL_PRIVATE_DO_NOT_ROOT_HTTP_OR_EDGE_PROVENANCE'))
DELTA_SOURCES = frozenset(('package-lock.json', 'package.json', 'qualification/rendezvous/allocation-budget.ts', 'qualification/rendezvous/assertion-key-state.check.mjs', 'qualification/rendezvous/enrollment-evidence-candidate.mjs', 'qualification/rendezvous/enrollment-evidence.check.mjs', 'qualification/rendezvous/enrollment-key-state.check.mjs', 'qualification/rendezvous/provider-unavailable.check.mjs', 'qualification/rendezvous/request-admission.check.mjs', 'qualification/rendezvous/request-admission.ts', 'qualification/rendezvous/run_challenge_budget_workerd.mjs', 'qualification/rendezvous/run_shared_key_workerd.mjs', 'rendezvous-build-inputs.json', 'scripts/qualify_rendezvous_product_build.mjs', 'src/index.ts', 'src/rendezvous/composition.ts'))
DELTA_ADDITIONS = frozenset(('qualification/rendezvous/compatible-runtime-dependency-provenance-v3.json', 'src/surface-push/apns.ts', 'src/surface-push/composition.ts', 'src/surface-push/crypto.ts', 'src/surface-push/dispatch.ts', 'src/surface-push/enrollment-wire.ts', 'src/surface-push/enrollment.ts', 'src/surface-push/handler.ts', 'src/surface-push/issuer-wire.ts', 'src/surface-push/issuer.ts', 'src/surface-push/provider.ts', 'src/surface-push/store.ts', 'src/surface-push/wire.ts'))
REFERENCE_DELTA = {'THIRD_PARTY_NOTICES.md': {'before': '6d6319ca3c47afc56d3d90a36533c97954c4f0e2f8234a15f179309b65be564e', 'after': '9809ddd902af8e05a2fe651476437aac6f2f54534774a4cc98e4afe798422c6f'}, 'docs/rendezvous/THIRD_PARTY_LICENSES_V1.md': {'before': 'd01864598df3730714db3065143f08cb6d21765f3323f0c8db20c7f5f9e60442', 'after': 'c1475aaa3964043219feb95d430bb53a7b8151e230e88c569cd3e72e07f36f0e'}}
INSTALLED_DEPENDENCY_DELTA = {'node_modules/@noble/hashes/_md.js': {'before': None, 'after': '60cf3010fda89e3e4d3f0e7ff1ce249e9c467f34b4fd41b6fd6101d9f69be763'}, 'node_modules/@noble/hashes/_u64.js': {'before': None, 'after': 'b09da8c07fe8187c07649494cdb7cd0bcf13df90b506a9473d19e4d5f8c2e102'}, 'node_modules/@noble/hashes/esm/_md.js': {'before': 'cefb1557e7715cb2117c83f82ef3e3175c7e0391c80bd5795b2d4effc45fc582', 'after': None}, 'node_modules/@noble/hashes/esm/_u64.js': {'before': 'e48c0cfc10810439a4807b46db136ce603a3fa09b62584f513ef2f3ca496af54', 'after': None}, 'node_modules/@noble/hashes/esm/crypto.js': {'before': '9211d026c5d21e60e0126dd6f01150d87da5ba7261b8f468215c1264372ff5a5', 'after': None}, 'node_modules/@noble/hashes/esm/legacy.js': {'before': '4906186a82438392443e3ac2a59d0acbbec2bee2595d048c8d8c0dd6584d4bdb', 'after': None}, 'node_modules/@noble/hashes/esm/sha1.js': {'before': 'cd708647a4aad36d820253fc75e3a821efe842652b2c9134903c5aec33a2926a', 'after': None}, 'node_modules/@noble/hashes/esm/sha2.js': {'before': 'e729088b82e5450bff54c3a0013582aa42e1fe8f58dd31f5967f6ebe34c52299', 'after': None}, 'node_modules/@noble/hashes/esm/utils.js': {'before': '4cf4c1e05affedcb4fd584a43d76ae1a3711e34a36e2251b90c27e33ecc74fad', 'after': None}, 'node_modules/@noble/hashes/legacy.js': {'before': None, 'after': '690553a41af2fdd1e32ff6b534ba8508e95f1861c09c2d62fe762b6b501e09be'}, 'node_modules/@noble/hashes/sha2.js': {'before': None, 'after': '471746bba6ec4c6238ca41358d1d3b40b6ff31cf3363f0b4d550c649c1a8e83b'}, 'node_modules/@noble/hashes/utils.js': {'before': None, 'after': '037ad49adb78168b6b699598fd33f85f7877456b1d28b4d032e2a1a16807947c'}, 'node_modules/@peculiar/utils/build/_virtual/_rolldown/runtime.js': {'before': None, 'after': '1b10431e13b4eb349c329aba7d2beb6e6c224de569eac52966731c8239a941c9'}, 'node_modules/@peculiar/utils/build/bytes.js': {'before': None, 'after': '3257233f9027e4bd4db558cbe9dd29a1bece8395f5c699eabf04169e38b02779'}, 'node_modules/@peculiar/utils/build/bytes/buffer-source.js': {'before': None, 'after': 'd3a77cab2b8426ce297e8429b9d2ba03dbdbe97865b8173c51da0c92226b0f49'}, 'node_modules/@peculiar/utils/build/bytes/concat.js': {'before': None, 'after': '0d7017fef27635bed4dfed715736209bdf8e6959953549be15fc79cb103f8ea9'}, 'node_modules/@peculiar/utils/build/bytes/equal.js': {'before': None, 'after': '535bd6636af131a226dc59dd3642c4edb787611b71d78b94693b16523c5bd950'}, 'node_modules/@peculiar/utils/build/bytes/sequence.js': {'before': None, 'after': '771d13453aa579693ff8f1538ee754a8a21921bd910fe97bb571bddea572a4e1'}, 'node_modules/@peculiar/utils/build/converters/convert.js': {'before': None, 'after': '86c63126f664051c739c52945ce076a4aeb1171da95ddf78dba7d95886b80a8c'}, 'node_modules/@peculiar/utils/build/converters/defaults.js': {'before': None, 'after': '1781d65e5ebe30b2340b023bbcfff40fb9cee2e70918ce7e7f0c84999bd2fd7e'}, 'node_modules/@peculiar/utils/build/converters/registry.js': {'before': None, 'after': '162d1ba3bdbc3d014a9c48bd8c5aa325f5eb8a958104c7fe03d7ea8ef1319b40'}, 'node_modules/@peculiar/utils/build/encoding/base64.js': {'before': None, 'after': '98b0130b60565fcadfed4aa50b8854de6eafe9c224dbd2c5c994c673a50066c4'}, 'node_modules/@peculiar/utils/build/encoding/base64url.js': {'before': None, 'after': 'a2131390bb30cce0d6ab42ff32e056f7d665552449cb1829787a3001fae9add1'}, 'node_modules/@peculiar/utils/build/encoding/binary.js': {'before': None, 'after': '92727e40c10bb92f0bcf9b8841590ef11df1764b3027be3041e44f04edf56794'}, 'node_modules/@peculiar/utils/build/encoding/hex.js': {'before': None, 'after': 'a7066c019c44348f1d1fa6bb1972bf368a304af41b04e2dff3e4805a5cef81e0'}, 'node_modules/@peculiar/utils/build/encoding/utf16.js': {'before': None, 'after': '20ce0b98604a618599e5831158f94a032f94aa0a50c0e280dea776656a7f166c'}, 'node_modules/@peculiar/utils/build/encoding/utf8.js': {'before': None, 'after': 'd0e538af363ad2c92b6578f62902d6a374e94b34c7e90a9f5261743642c7c8a5'}, 'node_modules/@peculiar/utils/build/index.js': {'before': None, 'after': '249fb0a4cf5b6dd1cbc12f2c109d9ad5afa55fc34f6696db8a971b09efc6ad36'}, 'node_modules/@peculiar/utils/build/integer/int.js': {'before': None, 'after': '0b2523f5a56762ebc749a77ecd9f8ad1914d1240300efffd7ac87926b27c31b5'}, 'node_modules/@peculiar/utils/build/integer/uint.js': {'before': None, 'after': '53609f035e2e0513d1321147b5dbb8cf8ce483cd0fa3023e61a70dd1e0f85bab'}, 'node_modules/@peculiar/utils/build/legacy/buffer-source-converter.js': {'before': None, 'after': '61261697f592eefdda6393751447b22db37708d8cef7b42ecb79e69c366c2a67'}, 'node_modules/@peculiar/utils/build/legacy/convert.js': {'before': None, 'after': 'd604e5ffd876889bb177cf9ec2ebef468bc165ac7ffe28d2ab87736cc4263a6f'}, 'node_modules/@peculiar/utils/build/legacy/functions.js': {'before': None, 'after': 'be5e4255b7b45de3415b35f136656f3e44a413577740622a90ecea8b32e02b5f'}, 'node_modules/@peculiar/utils/build/pem/pem.js': {'before': None, 'after': '4204fe9f301df4cb96ed08ededb41934ec33e784d3aab1a31af3b9867184520b'}, 'node_modules/asn1js/build/index.es.js': {'before': 'ee1dbac2b2f8bc0edd15f56932d847f5a8565b20d0b2b22d6c978360279899e4', 'after': None}, 'node_modules/asn1js/build/index.js': {'before': None, 'after': '4a3cfe45a598edb62cbfcf89426f6a2556dd505bf3838935c106829fbfe32024'}, 'node_modules/bytestreamjs/build/bit.js': {'before': None, 'after': 'a3b2c1f5f923a1ed39b55745a4e501b2b6092b081c380acc73a542456e6687f9'}, 'node_modules/bytestreamjs/build/bit_stream.js': {'before': None, 'after': '220bc62673ddcbd43073d2f1f056c3da3ed6a4f44dc183af569b2e7a876ecca4'}, 'node_modules/bytestreamjs/build/byte_stream.js': {'before': None, 'after': '1dec0f7089d75334e9b58ae9b4690879dd88043cd3f377e9af4b20f9f0ff1b39'}, 'node_modules/bytestreamjs/build/helpers.js': {'before': None, 'after': '0e8003c7739767109d5a4931dde4c3aedec18100b5a3e3bc327d560cb6ef606c'}, 'node_modules/bytestreamjs/build/index.js': {'before': None, 'after': '4794bc465f13842696ec8c1ad027de9c198ad55c3c482059fe1694204833ebc2'}, 'node_modules/bytestreamjs/build/mjs/bit.js': {'before': '948aa3449ba484a4b33b8d251714a655ec67544e991902cd1773cab0c8cc1bfe', 'after': None}, 'node_modules/bytestreamjs/build/mjs/bit_stream.js': {'before': '109291e1cfc9e95db75748154cffd39163145d66fd85a6240d28eb5d8335c2f8', 'after': None}, 'node_modules/bytestreamjs/build/mjs/byte_stream.js': {'before': 'd265091e6b5209c1839b2c3f4d91df681a37bb1d3e3834891619d422277b634c', 'after': None}, 'node_modules/bytestreamjs/build/mjs/helpers.js': {'before': '9fe919254ac3db6db045e008cce021c5223146d8d9fbb2b3c5aa45a9ec1b2abf', 'after': None}, 'node_modules/bytestreamjs/build/mjs/index.js': {'before': '3139b1bdc36c99c155d14ff24e46ae5f3ecf78900f56de49bd466da2ed022de1', 'after': None}, 'node_modules/bytestreamjs/build/mjs/seq_bit_stream.js': {'before': '01b075ad7bc1c49fa2854cbe3c82407c29f12d01a926e0e77c68fe266159e5f8', 'after': None}, 'node_modules/bytestreamjs/build/mjs/seq_stream.js': {'before': 'bfa20e5092a8b5387091c9b00133a0fcaedf8bff090840cbb3872045346c1dc4', 'after': None}, 'node_modules/bytestreamjs/build/seq_bit_stream.js': {'before': None, 'after': '656eb46b51688d11ca3eb6b673e5d9f7c837727378676447da564b9a9416518e'}, 'node_modules/bytestreamjs/build/seq_stream.js': {'before': None, 'after': '6d5446062668db78d3ca06dbf75f5a76544347a93781af69c458f6448b17a6b4'}, 'node_modules/pkijs/build/index.es.js': {'before': '5f5c08540929f01ee75373b9f317753aeb6a7239241658473bb37826e2f85a50', 'after': None}, 'node_modules/pkijs/build/index.js': {'before': None, 'after': '81323b7ffbe635d9fbfeef6cb6db6166c8c1a9ff6e4b1158a4c09515ab8c1685'}, 'node_modules/pvtsutils/build/index.js': {'before': '8cf4300225298c7811fd72840f84ebd12dda5359f29fffdba09cb67a63a5943f', 'after': None}, 'node_modules/pvutils/build/utils.es.js': {'before': 'e1a942c322462a4a2b1a2311b2b40bd9ab1779273d98fca085e074532f96db98', 'after': None}}
SOURCE_PROVENANCE = {'baseline_sha': '896ccdc69447c231d04da3a6af4f27ea1f763697', 'delta_sha256': '8353b2c06755d12ea08c304d6ddb4b691863ee0a774fc314bd95a938d85407e5', 'effective_source_map_sha256': 'e2d0a139879729c728ab89f85534987bbc28f95e47de9c05389f801a8028e239', 'kind': 'BASELINE_PLUS_PINNED_DELTA', 'closed_receiving_root_delta_sha256': 'c1aacd517175cd5a4a6ea976029af294b6fbc73fbe6013098d3c272aebb12628', 'closed_receiving_root_product_sha256': '1ae2f21996bf74c606ddfb80072dbe8f1c7bc87aa0f703821c35189e87ebff0a', 'closed_receiving_root_source_map_sha256': '5ca0758d825063e9dafcb519eef238d707d52d52fbc35d270d37af38c5c146fd', 'qualification_workflow_delta_sha256': '5af37a24c9dfe7ead48425ce3597f0d9eb6288c20bc8ca5e415b5f977a96d3f1', 'qualified_source_map_sha256': 'd75bef5d8a7ddcff4723639817f6f0e2c85967d528e9be3c2bbb0dc4fe1f5109'}

WORKFLOW_DELTA_PATH = 'docs/rendezvous/qualification-workflow-delta-v1.json'
WORKFLOW_DELTA_SHA256 = '5af37a24c9dfe7ead48425ce3597f0d9eb6288c20bc8ca5e415b5f977a96d3f1'
WORKFLOW_DELTA_SOURCE = '.github/workflows/ci-cd.yml'
SOURCE_PROVENANCE.update(qualification_workflow_delta_sha256=WORKFLOW_DELTA_SHA256,
    qualified_source_map_sha256='d75bef5d8a7ddcff4723639817f6f0e2c85967d528e9be3c2bbb0dc4fe1f5109')

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
        require(isinstance(recorded, dict) and len(recorded) == (66, 19, 116 if with_closed_issuer else 85)[index])
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
    require(len(excluded) == (50 if with_closed_issuer else 32) and len(sources) == (119 if with_closed_issuer else 106))
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


def qualification_workflow_delta(sources, references):
    # Retain all immutable runtime proofs. Only this exact, separately pinned
    # qualification-workflow input may differ from their historical source map.
    delta = pinned_working_proof(WORKFLOW_DELTA_PATH, WORKFLOW_DELTA_SHA256)
    require(isinstance(delta, dict) and set(delta) == {'schema_version', 'scope', 'changes'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
        and delta['scope'] == 'EXACT_QUALIFICATION_WORKFLOW_DELTA_NOT_RUNTIME_OR_ACTIVATION')
    changes = delta['changes']
    require(isinstance(changes, dict) and set(changes) == {WORKFLOW_DELTA_SOURCE})
    change = changes[WORKFLOW_DELTA_SOURCE]
    require(isinstance(change, dict) and set(change) == {'before', 'after'}
        and change['before'] == sources[WORKFLOW_DELTA_SOURCE]
        and change['after'] != change['before']
        and isinstance(change['after'], str) and len(change['after']) == 64
        and all(c in '0123456789abcdef' for c in change['after']))
    effective, refs = dict(sources), dict(references)
    effective[WORKFLOW_DELTA_SOURCE] = change['after']
    require(source_map_digest(effective) == SOURCE_PROVENANCE['qualified_source_map_sha256'])
    refs[WORKFLOW_DELTA_PATH] = WORKFLOW_DELTA_SHA256
    return effective, refs


CLOSED_RECEIVING_DELTA_PATH = 'docs/rendezvous/host-wake-closed-root-source-delta-v1.json'
CLOSED_RECEIVING_DELTA_SHA256 = 'c1aacd517175cd5a4a6ea976029af294b6fbc73fbe6013098d3c272aebb12628'
CLOSED_RECEIVING_PRODUCT_PATH = 'docs/rendezvous/host-wake-closed-root-product-observations-v1.json'
CLOSED_RECEIVING_PRODUCT_SHA256 = '1ae2f21996bf74c606ddfb80072dbe8f1c7bc87aa0f703821c35189e87ebff0a'
CLOSED_RECEIVING_MAP_CHANGES = frozenset(('coordinator/host-app-wake-receiving/authorization-resolve.ts', 'coordinator/host-app-wake-receiving/guard-schema.ts', 'coordinator/host-app-wake-receiving/native-apple-evidence.mjs', 'coordinator/host-app-wake-receiving/native-assertion.ts', 'coordinator/host-app-wake-receiving/native-attestation.ts', 'coordinator/host-app-wake-receiving/native-policy-store.ts', 'coordinator/host-app-wake-receiving/native-policy.ts', 'coordinator/host-app-wake-receiving/native-state.ts', 'coordinator/host-app-wake-receiving/operator-auth.ts', 'coordinator/host-app-wake-receiving/principal.ts', 'coordinator/host-app-wake-receiving/private-intake.ts', 'coordinator/host-app-wake-receiving/receiving-store.ts', 'coordinator/host-app-wake-receiving/request-window.ts', 'coordinator/host-app-wake-receiving/server-reply.ts', 'coordinator/host-app-wake-receiving/server-wire.ts', 'coordinator/host-app-wake-receiving/service.ts', 'coordinator/host-app-wake-receiving/source-backend.ts', 'coordinator/host-app-wake-receiving/target-transport.ts', 'coordinator/host-app-wake-receiving/wire.ts', 'coordinator/host-app-wake/service.ts', 'coordinator/host-app-wake/store.ts', 'coordinator/host-app-wake/wire.ts', 'scripts/qualify_rendezvous_product_build.mjs', 'src/host-wake-receiving/dispatch.ts', 'src/index.ts'))


def closed_receiving_root_delta(sources, references):
    # Preserve every historical source/proof. Only this new exact additive
    # closed-root import closure may differ; it is no activation approval.
    delta = pinned_working_proof(CLOSED_RECEIVING_DELTA_PATH, CLOSED_RECEIVING_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'protected_source_parent', 'baseline_source_map_sha256', 'effective_source_map_sha256', 'changes', 'product_proof', 'map_additions_are_newly_compiled_inputs_not_claimed_git_additions', 'public_activation_allowed'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1 and delta['scope'] == 'EXACT_CLOSED_RECEIVING_ROOT_SOURCE_DELTA_NOT_ACTIVATION')
    require(delta['public_activation_allowed'] is False and delta['map_additions_are_newly_compiled_inputs_not_claimed_git_additions'] is True)
    require(delta['protected_source_parent'] == '2f56dbf6d58f882c2dd586dadb87734e044e95f3')
    require(delta['baseline_source_map_sha256'] == source_map_digest(sources))
    require(set(delta['changes']) == CLOSED_RECEIVING_MAP_CHANGES)
    effective, refs = dict(sources), dict(references)
    for name, change in delta['changes'].items():
        safe_path(name)
        require(set(change) == {'before', 'after'} and change['before'] == sources.get(name)
                and change['after'] != change['before'] and isinstance(change['after'], str)
                and len(change['after']) == 64 and all(c in '0123456789abcdef' for c in change['after']))
        effective[name] = change['after']
    require(delta['effective_source_map_sha256'] == source_map_digest(effective)
            == SOURCE_PROVENANCE['closed_receiving_root_source_map_sha256'])
    product = pinned_working_proof(CLOSED_RECEIVING_PRODUCT_PATH, CLOSED_RECEIVING_PRODUCT_SHA256)
    require(product['scope'] == 'ACTUAL_PRODUCT_BUILD_PRIVATE_RPC_ONLY' and product['result'] == 'PASS'
            and product['checks'] == 128 and product['closed_receiving_prefix_checks'] == 64
            and product['outbound_calls'] == 0 and product['native_positive_accepted'] is False
            and product['service_activated'] is False and product['cloudflare_mutations'] is False)
    require(delta['product_proof'] == {'path': CLOSED_RECEIVING_PRODUCT_PATH,
        'sha256': CLOSED_RECEIVING_PRODUCT_SHA256, 'legacy_checks': 128,
        'closed_receiving_prefix_checks': 64, 'installed_dependency_inputs_unchanged': 50})
    old_product = pinned_working_proof(DELTA_PROOFS[1][0], DELTA_PROOFS[1][1])
    installed = lambda p: {k: v for k, v in p['source_hashes'].items() if k.startswith('node_modules/')}
    require(installed(product) == installed(old_product) and len(installed(product)) == 50)
    for name, expected in product['source_hashes'].items():
        # Offline preparation validates installed bytes through both immutable
        # original build maps; it never needs or treats an installation as authority.
        if name.startswith('node_modules/'):
            continue
        require(effective.get(name) == expected)
        # Only exact pinned source-delta layers may supersede historical bytes.
        # validate() checks EVERY effective input after applying those layers.
        if name not in CATEGORY_SOURCES | MOUNT_SOURCES | DEPENDENCY_SOURCES | WATCH_SOURCES | RECEIPT_SOURCES | RELEASE_RETENTION_SOURCES:
            require(digest(safe_path(name).read_bytes()) == expected)
    refs[CLOSED_RECEIVING_DELTA_PATH] = CLOSED_RECEIVING_DELTA_SHA256
    refs[CLOSED_RECEIVING_PRODUCT_PATH] = CLOSED_RECEIVING_PRODUCT_SHA256
    return effective, refs


def baseline_before_receiving_root():
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
    return qualification_workflow_delta(effective, references)


def baseline_before_ci_retention():
    return closed_receiving_root_delta(*baseline_before_receiving_root())


RETENTION_DELTA_PATH = 'docs/rendezvous/active-ci-retention-source-delta-v1.json'
RETENTION_DELTA_SHA256 = 'a474ec1ca6579b0892348be55c06ab0122105615d379f7727357b4a401ce56db'
RETENTION_SOURCE_MAP_SHA256 = '7afaaefbee37a68f003badc1a2426fd9e02fe90ff3fe4a7e4ddff2198e035bfa'
RETENTION_SOURCES = frozenset(('.github/workflows/ci-cd.yml', 'scripts/cleanup_workflow_runs.py', 'scripts/test_cleanup_workflow_runs.py'))
SOURCE_PROVENANCE.update(active_ci_retention_delta_sha256=RETENTION_DELTA_SHA256,
                         active_ci_retention_source_map_sha256=RETENTION_SOURCE_MAP_SHA256)


def baseline_before_native_category():
    sources, refs = baseline_before_ci_retention()
    delta = pinned_working_proof(RETENTION_DELTA_PATH, RETENTION_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'base_source',
            'baseline_source_map_sha256', 'effective_source_map_sha256',
            'changes', 'public_activation_allowed'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_ACTIVE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'
            and delta['base_source'] == 'b28a32e8fe80d612009c35a82961dba9c993e986'
            and delta['public_activation_allowed'] is False)
    require(delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['changes']) == RETENTION_SOURCES)
    effective = dict(sources)
    for name, change in delta['changes'].items():
        require(set(change) == {'before', 'after'} and change['before'] == sources.get(name)
                and change['before'] != change['after'] and isinstance(change['after'], str)
                and len(change['after']) == 64 and all(c in '0123456789abcdef' for c in change['after']))
        effective[name] = change['after']
    require(delta['effective_source_map_sha256'] == source_map_digest(effective)
            == RETENTION_SOURCE_MAP_SHA256)
    references = dict(refs)
    references[RETENTION_DELTA_PATH] = RETENTION_DELTA_SHA256
    return effective, references


CATEGORY_DELTA_PATH = 'docs/rendezvous/native-first-category-source-delta-v1.json'
CATEGORY_DELTA_SHA256 = '6c0a6e47f00057881fd4ecdab64c626c91a583617fe5ae6376c62cafbf06960e'
CATEGORY_SOURCE_MAP_SHA256 = '04dfade9e9e2573c27b1640f14a309a1f9f6feee0ea69d97f5b95c27713b6096'
CATEGORY_SOURCES = frozenset(('coordinator/host-app-wake-receiving/guard-schema.ts', 'coordinator/host-app-wake-receiving/native-apple-evidence.mjs', 'coordinator/host-app-wake-receiving/native-attestation.ts', 'coordinator/host-app-wake-receiving/native-policy.ts', 'coordinator/host-app-wake-receiving/native-state.ts'))
SOURCE_PROVENANCE.update(native_first_category_delta_sha256=CATEGORY_DELTA_SHA256,
                         native_first_category_source_map_sha256=CATEGORY_SOURCE_MAP_SHA256)


def baseline_before_private_mount():
    sources, refs = baseline_before_native_category()
    delta = pinned_working_proof(CATEGORY_DELTA_PATH, CATEGORY_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'base_source', 'baseline_source_map_sha256',
                           'effective_source_map_sha256', 'changes', 'public_activation_allowed'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_PRIVATE_FIRST_CATEGORY_SOURCE_NOT_ACTIVATION'
            and delta['base_source'] == '41549dadff8efb2da5fa0ab23ff7abeff86e19df'
            and delta['public_activation_allowed'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['changes']) == CATEGORY_SOURCES)
    effective = dict(sources)
    for name, change in delta['changes'].items():
        require(set(change) == {'before', 'after'} and change['before'] == sources[name]
                and change['after'] != change['before'] and isinstance(change['after'], str)
                and len(change['after']) == 64 and all(c in '0123456789abcdef' for c in change['after']))
        effective[name] = change['after']
    require(delta['effective_source_map_sha256'] == source_map_digest(effective)
            == CATEGORY_SOURCE_MAP_SHA256)
    refs = dict(refs)
    refs[CATEGORY_DELTA_PATH] = CATEGORY_DELTA_SHA256
    return effective, refs


MOUNT_DELTA_PATH = 'docs/rendezvous/private-receiving-mount-source-delta-v1.json'
MOUNT_DELTA_SHA256 = '8d4c6f7343c37bea54ac53709dd49d1c01e28a2d2ebe19a0102448cc7fccc960'
MOUNT_SOURCE_MAP_SHA256 = 'b734d7cdb32ef1785d40f3be6c2b6779b5203adf909c8fb4de48c78e12ac7b43'
MOUNT_SOURCES = frozenset(('coordinator/host-app-wake-receiving/operator-auth.ts', 'coordinator/host-app-wake-receiving/service.ts', 'scripts/qualify_rendezvous_product_build.mjs', 'src/host-wake-receiving/dispatch.ts'))
SOURCE_PROVENANCE.update(private_receiving_mount_delta_sha256=MOUNT_DELTA_SHA256,
                         private_receiving_mount_source_map_sha256=MOUNT_SOURCE_MAP_SHA256)


def baseline_before_dependency_refresh():
    sources, refs = baseline_before_private_mount()
    delta = pinned_working_proof(MOUNT_DELTA_PATH, MOUNT_DELTA_SHA256)
    require(set(delta) == {'schema_version','scope','base_source','baseline_source_map_sha256',
            'effective_source_map_sha256','changes','private_http_mount_selected','production_effect_authorized'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_PRIVATE_RECEIVING_MOUNT_NOT_EFFECT_AUTHORIZATION'
            and delta['base_source'] == '067a214b8f59524481ec1309d07cfa8270abb20f'
            and delta['private_http_mount_selected'] is True and delta['production_effect_authorized'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['changes']) == MOUNT_SOURCES)
    effective = dict(sources)
    for name, change in delta['changes'].items():
        require(set(change) == {'before','after'} and change['before'] == sources[name]
                and change['after'] != change['before'] and isinstance(change['after'], str)
                and len(change['after']) == 64 and all(c in '0123456789abcdef' for c in change['after']))
        effective[name] = change['after']
    require(delta['effective_source_map_sha256'] == source_map_digest(effective) == MOUNT_SOURCE_MAP_SHA256)
    refs = dict(refs)
    refs[MOUNT_DELTA_PATH] = MOUNT_DELTA_SHA256
    return effective, refs



DEPENDENCY_DELTA_PATH = 'docs/rendezvous/pkijs-wrangler-dependency-refresh-source-delta-v1.json'
DEPENDENCY_DELTA_SHA256 = 'd72223211a34f4556515499ffa4ea6e77ba931cba5b6febf9121d3748f6aeca2'
DEPENDENCY_SOURCE_MAP_SHA256 = '272aeb7fb48586102d9e5dc6bab70724857539a022e7b2446c4e24ac9e40c1db'
DEPENDENCY_SOURCES = frozenset(('package-lock.json', 'package.json', 'qualification/rendezvous/run_challenge_budget_workerd.mjs', 'qualification/rendezvous/run_shared_key_workerd.mjs', 'rendezvous-build-inputs.json', 'scripts/qualify_rendezvous_product_build.mjs'))
DEPENDENCY_ADDITIONS = frozenset(('qualification/rendezvous/compatible-runtime-dependency-provenance-v4.json',))
DEPENDENCY_REFERENCE_CHANGES = frozenset(('THIRD_PARTY_NOTICES.md', 'docs/rendezvous/THIRD_PARTY_LICENSES_V1.md'))
DEPENDENCY_REFERENCE_ADDITIONS = frozenset(('coordinator/host-app-wake-receiving/runtime/source-inputs.json', 'coordinator/host-app-wake/source-manifest.json', 'coordinator/installation-principal/source-manifest.json', 'coordinator/principal-possession/source-manifest.json', 'coordinator/rich-delivery/source-manifest.json', 'coordinator/rich-session/source-manifest.json', 'coordinator/worker-do/source-manifest.json'))
DEPENDENCY_INSTALLED_CHANGE = {'node_modules/pkijs/build/index.js': {'before': '81323b7ffbe635d9fbfeef6cb6db6166c8c1a9ff6e4b1158a4c09515ab8c1685', 'after': 'fcd402426e202ea647e51e0a1150cee1e66e41e1e18c2e7ef8cea013c92488c4'}}
SOURCE_PROVENANCE.update(dependency_refresh_delta_sha256=DEPENDENCY_DELTA_SHA256,
                         dependency_refresh_source_map_sha256=DEPENDENCY_SOURCE_MAP_SHA256)


def baseline_before_watch_topic():
    sources, refs = baseline_before_dependency_refresh()
    delta = pinned_working_proof(DEPENDENCY_DELTA_PATH, DEPENDENCY_DELTA_SHA256)
    require(set(delta) == {'schema_version','scope','base_source','baseline_source_map_sha256',
            'effective_source_map_sha256','source_changes','source_additions','reference_changes',
            'reference_additions','installed_changes','public_activation_allowed','production_effect_authorized'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_PKIJS_WRANGLER_DEPENDENCY_REFRESH_NOT_ACTIVATION'
            and delta['base_source'] == 'f156c3049a6320bc16d084b4b17b526090ccb7a7'
            and delta['public_activation_allowed'] is False and delta['production_effect_authorized'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['source_changes']) == DEPENDENCY_SOURCES
            and set(delta['source_additions']) == DEPENDENCY_ADDITIONS
            and set(delta['reference_changes']) == DEPENDENCY_REFERENCE_CHANGES
            and set(delta['reference_additions']) == DEPENDENCY_REFERENCE_ADDITIONS
            and delta['installed_changes'] == DEPENDENCY_INSTALLED_CHANGE)
    valid_hash = lambda h: isinstance(h, str) and len(h) == 64 and all(c in '0123456789abcdef' for c in h)
    effective, refs = dict(sources), dict(refs)
    for name, change in delta['source_changes'].items():
        require(set(change) == {'before','after'} and change['before'] == sources[name]
                and change['after'] != change['before'] and valid_hash(change['after']))
        effective[name] = change['after']
    for name, pin in delta['source_additions'].items():
        require(name not in effective and valid_hash(pin))
        effective[name] = pin
    require(source_map_digest(effective) == delta['effective_source_map_sha256'] == DEPENDENCY_SOURCE_MAP_SHA256)
    for name, change in delta['reference_changes'].items():
        require(set(change) == {'before','after'} and change['before'] == refs[name]
                and change['after'] != change['before'] and valid_hash(change['after']))
        refs[name] = change['after']
    for name, pin in delta['reference_additions'].items():
        require(name not in refs and valid_hash(pin))
        refs[name] = pin
    previous = pinned_working_proof(CLOSED_RECEIVING_PRODUCT_PATH, CLOSED_RECEIVING_PRODUCT_SHA256)
    installed = {k: h for k, h in previous['source_hashes'].items() if k.startswith('node_modules/')}
    for name, change in DEPENDENCY_INSTALLED_CHANGE.items():
        require(installed[name] == change['before'] and valid_hash(change['after']))
        installed[name] = change['after']
    provenance = pinned_working_proof('qualification/rendezvous/compatible-runtime-dependency-provenance-v4.json', effective['qualification/rendezvous/compatible-runtime-dependency-provenance-v4.json'])
    require(provenance['installed_inputs_sha256'] == installed and len(installed) == 50
            and provenance['installed_changes'] == DEPENDENCY_INSTALLED_CHANGE
            and provenance['unchanged_installed_inputs'] == 49
            and provenance['real_native_or_production_effect'] is False)
    refs[DEPENDENCY_DELTA_PATH] = DEPENDENCY_DELTA_SHA256
    return effective, refs


WATCH_DELTA_PATH = 'docs/rendezvous/watch-topic-source-delta-v1.json'
WATCH_DELTA_SHA256 = 'ea503efa3a57c86df670cfe2ab4ca5d02cee1d44e9ffef1446f06b6f177a85af'
WATCH_SOURCE_MAP_SHA256 = 'e2d62207b25cb2435be51dfcbe5a4ef8a7254b8e4e920b6451ae944b060fec85'
WATCH_SOURCES = frozenset(('wrangler.jsonc', 'rendezvous-build-inputs.json'))
WATCH_REFERENCES = frozenset(('wrangler.jsonc', 'coordinator/host-app-wake/source-manifest.json', 'coordinator/installation-principal/source-manifest.json', 'coordinator/principal-possession/source-manifest.json', 'coordinator/rich-session/source-manifest.json'))
SOURCE_PROVENANCE.update(watch_topic_delta_sha256=WATCH_DELTA_SHA256,
                         watch_topic_source_map_sha256=WATCH_SOURCE_MAP_SHA256)


def baseline_before_watch_registration_receipt():
    sources, refs = baseline_before_watch_topic()
    delta = pinned_working_proof(WATCH_DELTA_PATH, WATCH_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'base_source',
            'baseline_source_map_sha256', 'effective_source_map_sha256',
            'source_changes', 'reference_changes', 'public_activation_allowed',
            'production_effect_authorized'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_WATCH_TOPIC_ALIGNMENT_NOT_ACTIVATION'
            and delta['base_source'] == '7ac9ad160e1a8b0109262ea61d79c00bc94d659a'
            and delta['public_activation_allowed'] is False
            and delta['production_effect_authorized'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['source_changes']) == WATCH_SOURCES
            and set(delta['reference_changes']) == WATCH_REFERENCES)
    effective, references = dict(sources), dict(refs)
    for changes, original, result in ((delta['source_changes'], sources, effective),
                                      (delta['reference_changes'], refs, references)):
        for name, change in changes.items():
            require(set(change) == {'before', 'after'}
                    and change['before'] == original[name]
                    and change['after'] != change['before']
                    and isinstance(change['after'], str) and len(change['after']) == 64
                    and all(c in '0123456789abcdef' for c in change['after']))
            result[name] = change['after']
    require(source_map_digest(effective) == delta['effective_source_map_sha256']
            == WATCH_SOURCE_MAP_SHA256)
    require(delta['reference_changes']['wrangler.jsonc'] == delta['source_changes']['wrangler.jsonc'])
    references[WATCH_DELTA_PATH] = WATCH_DELTA_SHA256
    return effective, references


RECEIPT_DELTA_PATH = 'docs/rendezvous/watch-registration-receipt-source-delta-v1.json'
RECEIPT_DELTA_SHA256 = '77dc038adb870e61263e2fafba22994815dc5c191fd00ae94dd8719c6b3ff13c'
RECEIPT_SOURCE_MAP_SHA256 = 'f4e44f5a4221a0dbf4f1042fafb8c5c4ce8c927a6317da09b43e35c85010a938'
RECEIPT_SOURCES = frozenset(('src/repositories/registrations.ts',))
RECEIPT_REFERENCES = frozenset(('coordinator/host-app-wake-receiving/runtime/source-inputs.json',))
SOURCE_PROVENANCE.update(watch_registration_receipt_delta_sha256=RECEIPT_DELTA_SHA256,
                         watch_registration_receipt_source_map_sha256=RECEIPT_SOURCE_MAP_SHA256)


def baseline_before_release_retention():
    sources, refs = baseline_before_watch_registration_receipt()
    delta = pinned_working_proof(RECEIPT_DELTA_PATH, RECEIPT_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'base_source',
            'baseline_source_map_sha256', 'effective_source_map_sha256',
            'source_changes', 'reference_changes', 'public_activation_allowed',
            'production_effect_authorized'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_WATCH_REGISTRATION_RECEIPT_NOT_ACTIVATION'
            and delta['base_source'] == '176d71afe111a70028fef0d7ed2c28f41f66aaab'
            and delta['public_activation_allowed'] is False
            and delta['production_effect_authorized'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['source_changes']) == RECEIPT_SOURCES
            and set(delta['reference_changes']) == RECEIPT_REFERENCES)
    for changes, current in ((delta['source_changes'], sources), (delta['reference_changes'], refs)):
        for name, change in changes.items():
            require(set(change) == {'before', 'after'} and change['before'] == current[name]
                    and change['after'] != change['before']
                    and isinstance(change['after'], str) and len(change['after']) == 64
                    and all(c in '0123456789abcdef' for c in change['after']))
            current[name] = change['after']
    require(source_map_digest(sources) == delta['effective_source_map_sha256'] == RECEIPT_SOURCE_MAP_SHA256)
    refs[RECEIPT_DELTA_PATH] = RECEIPT_DELTA_SHA256
    return sources, refs


RELEASE_RETENTION_DELTA_PATH = 'docs/rendezvous/release-ci-retention-source-delta-v1.json'
RELEASE_RETENTION_DELTA_SHA256 = 'e57853f7ca1a0e7cab741fc6adbf2784bd86779605e9882a32098691345f2e0b'
RELEASE_RETENTION_SOURCE_MAP_SHA256 = '95ed9d508a33a905d807bc422c525a3b8a6fc5ee3920e8e0020f174c6a23cfc5'
RELEASE_RETENTION_SOURCES = frozenset(('.github/workflows/ci-cd.yml',))
SOURCE_PROVENANCE.update(release_ci_retention_delta_sha256=RELEASE_RETENTION_DELTA_SHA256,
                         release_ci_retention_source_map_sha256=RELEASE_RETENTION_SOURCE_MAP_SHA256)


def baseline_before_closed_production_bindings():
    sources, refs = baseline_before_release_retention()
    delta = pinned_working_proof(RELEASE_RETENTION_DELTA_PATH, RELEASE_RETENTION_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'base_source',
            'baseline_source_map_sha256', 'effective_source_map_sha256',
            'changes', 'public_activation_allowed'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_RELEASE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'
            and delta['base_source'] == '664f68f9d7798188513c8b59aa46424a158c4630'
            and delta['public_activation_allowed'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['changes']) == RELEASE_RETENTION_SOURCES)
    for name, change in delta['changes'].items():
        require(set(change) == {'before', 'after'} and change['before'] == sources[name]
                and change['after'] != change['before']
                and isinstance(change['after'], str) and len(change['after']) == 64
                and all(c in '0123456789abcdef' for c in change['after']))
        sources[name] = change['after']
    require(source_map_digest(sources) == delta['effective_source_map_sha256']
            == RELEASE_RETENTION_SOURCE_MAP_SHA256)
    refs[RELEASE_RETENTION_DELTA_PATH] = RELEASE_RETENTION_DELTA_SHA256
    return sources, refs


CLOSED_PRODUCTION_BINDINGS_DELTA_PATH = 'docs/rendezvous/closed-production-bindings-source-delta-v1.json'
CLOSED_PRODUCTION_BINDINGS_DELTA_SHA256 = 'd08c9ebdde24f4e14e9004c96ca17f43663adac0b58e4ed69fb7d5c9c25eca0d'
CLOSED_PRODUCTION_BINDINGS_SOURCE_MAP_SHA256 = '2ea924a5e904eb1e675f328be9a24ed5453cd62c2b040b7a5f90a31a3f10b950'
CLOSED_PRODUCTION_BINDINGS_SOURCES = frozenset(('wrangler.jsonc', 'rendezvous-build-inputs.json'))
SOURCE_PROVENANCE.update(closed_production_bindings_delta_sha256=CLOSED_PRODUCTION_BINDINGS_DELTA_SHA256,
                         closed_production_bindings_source_map_sha256=CLOSED_PRODUCTION_BINDINGS_SOURCE_MAP_SHA256)


def baseline():
    sources, refs = baseline_before_closed_production_bindings()
    delta = pinned_working_proof(CLOSED_PRODUCTION_BINDINGS_DELTA_PATH,
                                 CLOSED_PRODUCTION_BINDINGS_DELTA_SHA256)
    require(set(delta) == {'schema_version', 'scope', 'base_source', 'baseline_source_map_sha256',
                           'effective_source_map_sha256', 'changes', 'public_activation_allowed',
                           'production_effect_authorized'})
    require(type(delta['schema_version']) is int and delta['schema_version'] == 1
            and delta['scope'] == 'EXACT_CLOSED_PRODUCTION_BINDINGS_SOURCE_ONLY'
            and delta['base_source'] == 'd0827f5f84d765d87f6d29f61add7a4d9570c9e2'
            and delta['public_activation_allowed'] is False
            and delta['production_effect_authorized'] is False
            and delta['baseline_source_map_sha256'] == source_map_digest(sources)
            and set(delta['changes']) == CLOSED_PRODUCTION_BINDINGS_SOURCES)
    for name, change in delta['changes'].items():
        require(set(change) == {'before', 'after'} and change['before'] == sources[name]
                and change['after'] == digest(safe_path(name).read_bytes())
                and change['after'] != change['before'])
        sources[name] = change['after']
    require(source_map_digest(sources) == delta['effective_source_map_sha256']
            == CLOSED_PRODUCTION_BINDINGS_SOURCE_MAP_SHA256)
    refs['wrangler.jsonc'] = sources['wrangler.jsonc']
    refs[CLOSED_PRODUCTION_BINDINGS_DELTA_PATH] = CLOSED_PRODUCTION_BINDINGS_DELTA_SHA256
    return sources, refs


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
            'open_gate_count': len(GATES),
            'qualification_workflow_delta': pinned_working_proof(
                WORKFLOW_DELTA_PATH, WORKFLOW_DELTA_SHA256)['changes']}


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
