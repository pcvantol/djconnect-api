// API-owned local server experiment. No product endpoint, native target or activation.
import {createHash,randomBytes} from 'node:crypto';
import {createRequire} from 'node:module';
import {mkdtemp,readFile,writeFile,chmod,rm} from 'node:fs/promises';
import {resolve,join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {need,ROUTES} from './local-native-files.mjs';
import {statusOnlyOutbound,allowedStatusRequest} from './local-native-egress.mjs';
import {stage40381,check40381Graph,registrationRecoverController} from './private-profile-40381.mjs';

export const repo=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
const sha=v=>createHash('sha256').update(v).digest('hex');
const toolFiles=['qualification/rendezvous/local-native-files.mjs','qualification/rendezvous/local-native-egress.mjs','qualification/rendezvous/local-native-runtime.mjs','qualification/rendezvous/run-local-native.mjs','qualification/rendezvous/private-profile-40381.mjs','qualification/rendezvous/run-local-native-40381.mjs'];
export function gitRead(args){
 const env=Object.fromEntries(Object.entries(process.env).filter(([name])=>!name.startsWith('GIT_')));
 Object.assign(env,{GIT_NO_LAZY_FETCH:'1',GIT_TERMINAL_PROMPT:'0',GIT_OPTIONAL_LOCKS:'0',GIT_NO_REPLACE_OBJECTS:'1'});
 return spawnSync('git',args,{cwd:repo,env,encoding:'utf8',timeout:10000});
}
export async function checkSourcePins(pins,base){
 for(const [p,h] of Object.entries(pins)){need(!p.includes('..')&&!p.startsWith('/'));need(sha(await readFile(join(base,p)))===h);}
}
export async function sourceSnapshot(){
 const status=gitRead(['status','--porcelain','--untracked-files=normal']);need(status.status===0&&status.stdout==='');
 const checked=spawnSync('python3',['scripts/validate_rendezvous_deployment_plan.py'],{cwd:repo,encoding:'utf8',timeout:30000});
 need(checked.status===0);const preparation=JSON.parse(checked.stdout);need(preparation.activation_allowed===false);
 const plan=JSON.parse(await readFile(join(repo,'docs/rendezvous/deployment-preparation-v1.json')));
 const rootPath='docs/rendezvous/closed-enrollment-service-product-observations-v2.json';
 const rootRaw=await readFile(join(repo,rootPath));
 need(plan.reference_hashes[rootPath]===sha(rootRaw));
 const root=JSON.parse(rootRaw);
 // Retain both historical proofs and exact separately validated deltas.
 // No current checkout/JSON may replace an original proof or authorize native.
 const delta=preparation.qualification_workflow_delta;
 need(delta&&Object.keys(delta).join(',')==='.github/workflows/ci-cd.yml');
 const closedPath='docs/rendezvous/host-wake-closed-root-source-delta-v1.json';
 const closedRaw=await readFile(join(repo,closedPath)),provenance=preparation.source_provenance;
 need(plan.reference_hashes[closedPath]===sha(closedRaw)&&sha(closedRaw)===provenance.closed_receiving_root_delta_sha256);
 const closed=JSON.parse(closedRaw);
 need(closed.scope==='EXACT_CLOSED_RECEIVING_ROOT_SOURCE_DELTA_NOT_ACTIVATION'&&closed.public_activation_allowed===false);
 need(closed.baseline_source_map_sha256===provenance.qualified_source_map_sha256&&closed.effective_source_map_sha256===provenance.closed_receiving_root_source_map_sha256);
 const retentionPath='docs/rendezvous/active-ci-retention-source-delta-v1.json',retentionRaw=await readFile(join(repo,retentionPath));
 need(plan.reference_hashes[retentionPath]===sha(retentionRaw)&&sha(retentionRaw)===provenance.active_ci_retention_delta_sha256);
 const retention=JSON.parse(retentionRaw);
 need(retention.scope==='EXACT_ACTIVE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'&&retention.public_activation_allowed===false);
 need(retention.baseline_source_map_sha256===closed.effective_source_map_sha256&&retention.effective_source_map_sha256===provenance.active_ci_retention_source_map_sha256);
 const categoryPath='docs/rendezvous/native-first-category-source-delta-v1.json',categoryRaw=await readFile(join(repo,categoryPath));
 need(plan.reference_hashes[categoryPath]===sha(categoryRaw)&&sha(categoryRaw)===provenance.native_first_category_delta_sha256);
 const category=JSON.parse(categoryRaw);need(category.scope==='EXACT_PRIVATE_FIRST_CATEGORY_SOURCE_NOT_ACTIVATION'&&category.public_activation_allowed===false);
 need(category.baseline_source_map_sha256===retention.effective_source_map_sha256&&category.effective_source_map_sha256===provenance.native_first_category_source_map_sha256);
 const mountPath='docs/rendezvous/private-receiving-mount-source-delta-v1.json',mountRaw=await readFile(join(repo,mountPath));
 need(plan.reference_hashes[mountPath]===sha(mountRaw)&&sha(mountRaw)===provenance.private_receiving_mount_delta_sha256);
 const mount=JSON.parse(mountRaw);need(mount.scope==='EXACT_PRIVATE_RECEIVING_MOUNT_NOT_EFFECT_AUTHORIZATION'&&mount.private_http_mount_selected===true&&mount.production_effect_authorized===false);
 need(mount.baseline_source_map_sha256===category.effective_source_map_sha256&&mount.effective_source_map_sha256===provenance.private_receiving_mount_source_map_sha256);
 const dependencyPath='docs/rendezvous/pkijs-wrangler-dependency-refresh-source-delta-v1.json',dependencyRaw=await readFile(join(repo,dependencyPath));
 need(plan.reference_hashes[dependencyPath]===sha(dependencyRaw)&&sha(dependencyRaw)===provenance.dependency_refresh_delta_sha256);
 const dependency=JSON.parse(dependencyRaw);need(dependency.scope==='EXACT_PKIJS_WRANGLER_DEPENDENCY_REFRESH_NOT_ACTIVATION'&&dependency.public_activation_allowed===false&&dependency.production_effect_authorized===false);
 need(dependency.baseline_source_map_sha256===mount.effective_source_map_sha256&&dependency.effective_source_map_sha256===provenance.dependency_refresh_source_map_sha256);
 const watchPath='docs/rendezvous/watch-topic-source-delta-v1.json',watchRaw=await readFile(join(repo,watchPath));
 need(plan.reference_hashes[watchPath]===sha(watchRaw)&&sha(watchRaw)===provenance.watch_topic_delta_sha256);
 const watch=JSON.parse(watchRaw);need(watch.scope==='EXACT_WATCH_TOPIC_ALIGNMENT_NOT_ACTIVATION'&&watch.public_activation_allowed===false&&watch.production_effect_authorized===false);
 need(watch.baseline_source_map_sha256===dependency.effective_source_map_sha256&&watch.effective_source_map_sha256===provenance.watch_topic_source_map_sha256);
 const receiptPath='docs/rendezvous/watch-registration-receipt-source-delta-v1.json',receiptRaw=await readFile(join(repo,receiptPath));
 need(plan.reference_hashes[receiptPath]===sha(receiptRaw)&&sha(receiptRaw)===provenance.watch_registration_receipt_delta_sha256);
 const receipt=JSON.parse(receiptRaw);need(receipt.scope==='EXACT_WATCH_REGISTRATION_RECEIPT_NOT_ACTIVATION'&&receipt.public_activation_allowed===false&&receipt.production_effect_authorized===false);
 need(receipt.baseline_source_map_sha256===watch.effective_source_map_sha256&&receipt.effective_source_map_sha256===provenance.watch_registration_receipt_source_map_sha256);
 const releaseRetentionPath='docs/rendezvous/release-ci-retention-source-delta-v1.json',releaseRetentionRaw=await readFile(join(repo,releaseRetentionPath));
 need(plan.reference_hashes[releaseRetentionPath]===sha(releaseRetentionRaw)&&sha(releaseRetentionRaw)===provenance.release_ci_retention_delta_sha256);
 const releaseRetention=JSON.parse(releaseRetentionRaw);need(releaseRetention.scope==='EXACT_RELEASE_CI_RETENTION_SOURCE_ONLY_NOT_RUNTIME'&&releaseRetention.public_activation_allowed===false);
 need(releaseRetention.baseline_source_map_sha256===receipt.effective_source_map_sha256&&releaseRetention.effective_source_map_sha256===provenance.release_ci_retention_source_map_sha256);
 const bindingsPath='docs/rendezvous/closed-production-bindings-source-delta-v1.json';
 const bindingsRaw=await readFile(join(repo,bindingsPath));
 need(plan.reference_hashes[bindingsPath]===sha(bindingsRaw)&&sha(bindingsRaw)===provenance.closed_production_bindings_delta_sha256);
 const bindings=JSON.parse(bindingsRaw);
 need(bindings.scope==='EXACT_CLOSED_PRODUCTION_BINDINGS_SOURCE_ONLY'&&bindings.public_activation_allowed===false&&bindings.production_effect_authorized===false);
 need(bindings.baseline_source_map_sha256===releaseRetention.effective_source_map_sha256&&bindings.effective_source_map_sha256===provenance.closed_production_bindings_source_map_sha256);
 const toolchainPath='docs/rendezvous/toolchain-development-dependency-refresh-v1.json';
 const toolchainRaw=await readFile(join(repo,toolchainPath));
 need(plan.reference_hashes[toolchainPath]===sha(toolchainRaw)&&sha(toolchainRaw)===provenance.toolchain_refresh_delta_sha256);
 const toolchain=JSON.parse(toolchainRaw);
 need(toolchain.scope==='EXACT_TOOLCHAIN_AND_DEVELOPMENT_DEPENDENCY_REFRESH_NOT_ACTIVATION'&&toolchain.public_activation_allowed===false);
 need(toolchain.baseline_source_map_sha256===bindings.effective_source_map_sha256&&toolchain.effective_source_map_sha256===provenance.toolchain_refresh_source_map_sha256);
 const toolchainFiles=["package-lock.json","package.json","scripts/qualify_rendezvous_product_build.mjs"];
 need(Object.keys(toolchain.changes).length===toolchainFiles.length&&toolchainFiles.every(name=>Object.hasOwn(toolchain.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const maintenancePath='docs/rendezvous/api-maintenance-source-delta-v1.json';
 const maintenanceRaw=await readFile(join(repo,maintenancePath));
 need(plan.reference_hashes[maintenancePath]===sha(maintenanceRaw)&&sha(maintenanceRaw)===provenance.api_maintenance_delta_sha256);
 const maintenance=JSON.parse(maintenanceRaw);
 need(maintenance.scope==='EXACT_API_MAINTENANCE_SOURCE_ONLY_NOT_ACTIVATION'&&maintenance.public_activation_allowed===false);
 need(maintenance.baseline_source_map_sha256===toolchain.effective_source_map_sha256&&maintenance.effective_source_map_sha256===provenance.api_maintenance_source_map_sha256);
 const maintenanceFiles=["src/auth.ts","src/handlers/install.ts","src/messages.ts","src/repositories/installTokens.ts","src/repositories/registrations.ts"];
 need(Object.keys(maintenance.changes).length===maintenanceFiles.length&&maintenanceFiles.every(name=>Object.hasOwn(maintenance.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const stablePath='docs/rendezvous/stable-api-release-source-delta-v1.json';
 const stableRaw=await readFile(join(repo,stablePath));
 need(plan.reference_hashes[stablePath]===sha(stableRaw)&&sha(stableRaw)===provenance.stable_release_delta_sha256);
 const stable=JSON.parse(stableRaw);
 need(stable.scope==='EXACT_STABLE_API_RELEASE_METADATA_NOT_ACTIVATION'&&stable.public_activation_allowed===false);
 need(stable.baseline_source_map_sha256===maintenance.effective_source_map_sha256&&stable.effective_source_map_sha256===provenance.stable_release_source_map_sha256);
 const stableFiles=["package-lock.json","package.json","scripts/qualify_rendezvous_product_build.mjs","src/releaseMetadata.ts"];
 need(Object.keys(stable.changes).length===stableFiles.length&&stableFiles.every(name=>Object.hasOwn(stable.changes,name)&&Object.hasOwn(root.source_hashes,name)));
 const erasurePath='docs/rendezvous/push-erasure-source-delta-v1.json';
 const erasureRaw=await readFile(join(repo,erasurePath));
 need(plan.reference_hashes[erasurePath]===sha(erasureRaw)&&sha(erasureRaw)===provenance.push_erasure_delta_sha256);
 const erasure=JSON.parse(erasureRaw);
 need(erasure.scope==='EXACT_PUSH_ERASURE_SOURCE_NOT_RENDEZVOUS_ACTIVATION'&&erasure.public_activation_allowed===false);
 need(erasure.baseline_source_map_sha256===stable.effective_source_map_sha256&&erasure.effective_source_map_sha256===provenance.push_erasure_source_map_sha256);
 const keyAddressPath='docs/rendezvous/shared-key-address-delta-v1.json';
 const keyAddressRaw=await readFile(join(repo,keyAddressPath));
 need(plan.reference_hashes[keyAddressPath]===sha(keyAddressRaw)&&sha(keyAddressRaw)===provenance.shared_key_address_delta_sha256);
 const keyAddress=JSON.parse(keyAddressRaw);
 need(keyAddress.scope==='EXACT_SHARED_KEY_ADDRESS_DERIVATION_NOT_ACTIVATION'&&keyAddress.public_activation_allowed===false);
 need(keyAddress.baseline_source_map_sha256===erasure.effective_source_map_sha256&&keyAddress.effective_source_map_sha256===provenance.shared_key_address_source_map_sha256);
 const testFlightPath='docs/rendezvous/testflight-release-source-delta-v1.json';
 const testFlightRaw=await readFile(join(repo,testFlightPath));
 need(plan.reference_hashes[testFlightPath]===sha(testFlightRaw)&&sha(testFlightRaw)===provenance.testflight_profile_delta_sha256);
 const testFlight=JSON.parse(testFlightRaw);
 need(testFlight.scope==='EXACT_TESTFLIGHT_RELEASE_PROFILE_NOT_ACTIVATION'&&testFlight.public_activation_allowed===false);
 need(testFlight.baseline_source_map_sha256===keyAddress.effective_source_map_sha256&&testFlight.effective_source_map_sha256===provenance.testflight_profile_source_map_sha256);
 const publicTrialPath='docs/rendezvous/public-testflight-trial-source-delta-v1.json';
 const publicTrialRaw=await readFile(join(repo,publicTrialPath));
 need(plan.reference_hashes[publicTrialPath]===sha(publicTrialRaw)&&sha(publicTrialRaw)===provenance.public_trial_delta_sha256);
 const publicTrial=JSON.parse(publicTrialRaw);
 need(publicTrial.scope==='PUBLIC_TESTFLIGHT_TRIAL_CONFIGURED_NOT_DEPLOYED');
 need(publicTrial.baseline_source_map_sha256===testFlight.effective_source_map_sha256&&publicTrial.effective_source_map_sha256===provenance.public_trial_source_map_sha256);
 const alwaysOnPath='docs/rendezvous/always-on-testflight-source-delta-v1.json';
 const alwaysOnRaw=await readFile(join(repo,alwaysOnPath));
 need(plan.reference_hashes[alwaysOnPath]===sha(alwaysOnRaw)&&sha(alwaysOnRaw)===provenance.always_on_testflight_delta_sha256);
 const alwaysOn=JSON.parse(alwaysOnRaw);
 need(alwaysOn.scope==='PUBLIC_TESTFLIGHT_ALWAYS_ON_SOURCE_NOT_DEPLOYED');
 need(alwaysOn.baseline_source_map_sha256===publicTrial.effective_source_map_sha256&&alwaysOn.effective_source_map_sha256===provenance.always_on_testflight_source_map_sha256);
 const wranglerPath='docs/rendezvous/wrangler-4160-toolchain-source-delta-v1.json';
 const wranglerRaw=await readFile(join(repo,wranglerPath));
 need(plan.reference_hashes[wranglerPath]===sha(wranglerRaw)&&sha(wranglerRaw)===provenance.wrangler_4160_delta_sha256);
 const wrangler=JSON.parse(wranglerRaw);
 need(wrangler.scope==='EXACT_WRANGLER_4160_TOOLCHAIN_REFRESH_NOT_ACTIVATION'&&wrangler.public_activation_allowed===false);
 need(wrangler.baseline_source_map_sha256===alwaysOn.effective_source_map_sha256&&wrangler.effective_source_map_sha256===provenance.wrangler_4160_source_map_sha256);
 const governancePath='docs/rendezvous/org-governance-source-delta-v1.json';
 const governanceRaw=await readFile(join(repo,governancePath));
 need(plan.reference_hashes[governancePath]===sha(governanceRaw)&&sha(governanceRaw)===provenance.org_governance_delta_sha256);
 const governance=JSON.parse(governanceRaw);
 need(governance.scope==='EXACT_ORGANIZATION_GOVERNANCE_SOURCE_ONLY_NOT_ACTIVATION'&&governance.public_activation_allowed===false&&governance.production_effect_authorized===false);
 need(governance.baseline_source_map_sha256===wrangler.effective_source_map_sha256&&governance.effective_source_map_sha256===provenance.org_governance_source_map_sha256);
 const transitionPath='docs/rendezvous/core-governance-transition-source-delta-v1.json';
 const transitionRaw=await readFile(join(repo,transitionPath));
 need(plan.reference_hashes[transitionPath]===sha(transitionRaw)&&sha(transitionRaw)===provenance.core_governance_transition_delta_sha256);
 const transition=JSON.parse(transitionRaw);
 need(transition.scope==='EXACT_CORE_GOVERNANCE_WORKFLOW_TRANSITION_NOT_ACTIVATION'&&transition.public_activation_allowed===false&&transition.production_effect_authorized===false);
 need(transition.baseline_source_map_sha256===governance.effective_source_map_sha256&&transition.effective_source_map_sha256===provenance.core_governance_transition_source_map_sha256);
 const guardPath='docs/rendezvous/api-guard-reference-source-delta-v1.json';
 const guardRaw=await readFile(join(repo,guardPath));
 need(sha(guardRaw)==='a8ab1f34ef94c7c2ea44095d0b990b1d8ce25a59956aef83d32fda06aa38b32a'&&plan.reference_hashes[guardPath]===sha(guardRaw)&&provenance.api_guard_reference_delta_sha256===sha(guardRaw));
 const guard=JSON.parse(guardRaw),guardManifests=['coordinator/installation-principal/source-manifest.json','coordinator/principal-possession/source-manifest.json'];
 need(Object.keys(guard).sort().join(',')==='guard,manifest_changes,production_effect_authorized,public_activation_allowed,schema_version,scope'&&guard.schema_version===1&&guard.scope==='EXACT_API_GUARD_REFERENCE_SOURCE_ONLY_NOT_ACTIVATION'&&guard.public_activation_allowed===false&&guard.production_effect_authorized===false);
 need(Object.keys(guard.manifest_changes).sort().join(',')===guardManifests.join(',')&&Object.keys(guard.guard).sort().join(',')==='after,before,path');
 need(guard.guard.path==='scripts/check_reusable_workflow_refs.sh'&&guard.guard.before==='dd4f8093413999259d55bf950c2237f72d3e459bea0c43fae380b6774b8834b5'&&guard.guard.after==='6b127d78cfdfbcc65669ab43d2ab1967371cb9e136c691d882bf102adf68149c'&&sha(await readFile(join(repo,guard.guard.path)))===guard.guard.after);
 const orgReleasePath='docs/rendezvous/api-org-only-release-source-delta-v1.json';
 const orgReleaseRaw=await readFile(join(repo,orgReleasePath));
 need(sha(orgReleaseRaw)==='9cdcbdcf78e1990adb86daa388feed9bc4f92a40b3140dddce05acf61bd16e00'&&plan.reference_hashes[orgReleasePath]===sha(orgReleaseRaw)&&provenance.api_org_release_delta_sha256===sha(orgReleaseRaw));
 const orgRelease=JSON.parse(orgReleaseRaw),orgReleaseFiles=['.github/workflows/api-worker-post-deployment-smoke.yml','.github/workflows/deploy-api-worker.yml'];
 need(Object.keys(orgRelease).sort().join(',')==='production_effect_authorized,public_activation_allowed,reference_changes,schema_version,scope'&&orgRelease.schema_version===1&&orgRelease.scope==='EXACT_API_ORG_ONLY_RELEASE_SOURCE_NOT_ACTIVATION'&&orgRelease.public_activation_allowed===false&&orgRelease.production_effect_authorized===false);
 need(JSON.stringify(Object.keys(orgRelease.reference_changes).sort())===JSON.stringify(orgReleaseFiles));
 const identityPath='docs/rendezvous/api-core-identity-source-delta-v1.json';
 const identityRaw=await readFile(join(repo,identityPath));
 need(sha(identityRaw)==='dc2ef35dd624d60efb99b3048e3617bc214578e57449dc9e2a73e8901719e2ab'&&plan.reference_hashes[identityPath]===sha(identityRaw)&&provenance.api_core_identity_delta_sha256===sha(identityRaw));
 const identity=JSON.parse(identityRaw);
 need(identity.scope==='EXACT_API_CORE_IDENTITY_SOURCE_ONLY_NOT_ACTIVATION'&&identity.public_activation_allowed===false&&identity.production_effect_authorized===false);
 for(const name of orgReleaseFiles){const c=orgRelease.reference_changes[name];need(Object.keys(c).sort().join(',')==='after,before'&&c.before===identity.reference_changes[name].after&&plan.reference_hashes[name]===c.after&&sha(await readFile(join(repo,name)))===c.after);}
 const summaryPath='docs/rendezvous/api-governance-summary-pin-source-delta-v1.json';
 const summaryRaw=await readFile(join(repo,summaryPath));
 need(sha(summaryRaw)==='15a78327a997ada80926e8443715787951b2a18967a7ddaac90fa373cd6efd32'&&plan.reference_hashes[summaryPath]===sha(summaryRaw)&&provenance.api_governance_summary_pin_delta_sha256===sha(summaryRaw));
 const summary=JSON.parse(summaryRaw);
 need(Object.keys(summary).sort().join(',')==='manifest_changes,production_effect_authorized,public_activation_allowed,schema_version,scope,workflow_changes'&&summary.schema_version===1&&summary.scope==='EXACT_API_GOVERNANCE_SUMMARY_PIN_SOURCE_ONLY_NOT_ACTIVATION'&&summary.public_activation_allowed===false&&summary.production_effect_authorized===false);
 const sharedPath='docs/rendezvous/api-shared-governance-source-delta-v1.json';
 const sharedRaw=await readFile(join(repo,sharedPath));
 need(sha(sharedRaw)==='b9e44f138b5824cc29ca5fd99c3d822491486f2a720bb675303e65dc50a65376'&&plan.reference_hashes[sharedPath]===sha(sharedRaw)&&provenance.api_shared_governance_delta_sha256===sha(sharedRaw));
 const shared=JSON.parse(sharedRaw);
 need(shared.schema_version===1&&shared.scope==='EXACT_API_SHARED_GOVERNANCE_SOURCE_ONLY_NOT_ACTIVATION'&&shared.public_activation_allowed===false&&shared.production_effect_authorized===false);
 const sharedFiles=[".github/workflows/ci-cd.yml",".github/workflows/codeql.yml",".github/workflows/host-app-wake-receiving.yml",".github/workflows/host-app-wake-source.yml",".github/workflows/installation-principal-data.yml",".github/workflows/installation-registry-transactions.yml",".github/workflows/native-proof-data-journal.yml",".github/workflows/native-proof-transcript.yml",".github/workflows/principal-possession-data.yml",".github/workflows/push-coordinator-source.yml",".github/workflows/reusable-workflow-guard.yml",".github/workflows/rich-delivery-adapter.yml",".github/workflows/rich-session-data-profile.yml",".github/workflows/semgrep.yml",".github/workflows/surface-enrollment-source.yml",".github/workflows/watch-moment-alert-source.yml",".github/workflows/widget-first-key-source.yml",".github/workflows/worker-do-registry-source.yml"];
 need(JSON.stringify(Object.keys(shared.workflow_changes).sort())===JSON.stringify(sharedFiles));
 need(JSON.stringify(Object.keys(summary.workflow_changes).sort())===JSON.stringify(sharedFiles));
 const sharedOld='pcvantol/djconnect/.github/workflows/software-assurance-governance.yml@aabd5de46ae438478eb894707e5b1ea27aca8508';
 const sharedNew='djconnect-music-dj/djconnect-shared-workflows/.github/workflows/software-assurance-governance-aabd.yml@b4e6470be61fee895af0e13ca1a63f101f03d647';
 const sharedPrevious={};
 for(const name of sharedFiles){
  const current=await readFile(join(repo,name),'utf8'),latest=summary.workflow_changes[name],change=shared.workflow_changes[name];
  const newest='2a1c6fd2841b08630aee01402850f56840b50f70',previous='b4e6470be61fee895af0e13ca1a63f101f03d647';
  need(Object.keys(latest).sort().join(',')==='after,before'&&current.split(newest).length===2&&sha(Buffer.from(current))===latest.after);
  const text=current.replace(newest,previous);need(sha(Buffer.from(text))===latest.before);
  need(Object.keys(change).sort().join(',')==='after,before'&&text.split(sharedNew).length===2&&sha(Buffer.from(text))===change.after);
  sharedPrevious[name]=text.replace(sharedNew,sharedOld);
  need(sha(Buffer.from(sharedPrevious[name]))===change.before);
 }
 const sharedManifests=["coordinator/host-app-wake-receiving/runtime/source-inputs.json","coordinator/host-app-wake/source-manifest.json","coordinator/installation-principal/source-manifest.json","coordinator/installation-registry/source-manifest.json","coordinator/principal-possession/source-manifest.json","coordinator/rich-delivery/source-manifest.json","coordinator/rich-session/source-manifest.json","coordinator/source-manifest.json","coordinator/worker-do/source-manifest.json","qualification/watch-moment/source-manifest.json"];
 need(JSON.stringify(Object.keys(shared.manifest_changes).sort())===JSON.stringify(sharedManifests));
 need(JSON.stringify(Object.keys(summary.manifest_changes).sort())===JSON.stringify(sharedManifests));
 for(const name of sharedManifests){
  let text=await readFile(join(repo,name),'utf8');
  const latest=summary.manifest_changes[name],latestWorkflow=summary.workflow_changes[latest.workflow];
  need(Object.keys(latest).sort().join(',')==='after,before,workflow'&&latestWorkflow&&sha(Buffer.from(text))===latest.after&&text.split(latestWorkflow.after).length===2);
  text=text.replace(latestWorkflow.after,latestWorkflow.before);need(sha(Buffer.from(text))===latest.before);
  const change=shared.manifest_changes[name],workflow=shared.workflow_changes[change.workflow];need(latest.workflow===change.workflow);
  if(guardManifests.includes(name)){
   const update=guard.manifest_changes[name];
   need(Object.keys(update).sort().join(',')==='after,before'&&sha(Buffer.from(text))===update.after&&latest.before===update.after&&text.split(guard.guard.after).length===2);
   text=text.replace(guard.guard.after,guard.guard.before);
   need(sha(Buffer.from(text))===update.before&&update.before===change.after);
  }
  need(Object.keys(change).sort().join(',')==='after,before,workflow'&&workflow&&text.split(workflow.after).length===2&&sha(Buffer.from(text))===change.after);
  sharedPrevious[name]=text.replace(workflow.after,workflow.before);
  need(sha(Buffer.from(sharedPrevious[name]))===change.before);
 }
 need(JSON.stringify(Object.keys(shared.source_changes))===JSON.stringify(['.github/workflows/ci-cd.yml']));
 const sharedReferenceFiles=['.github/workflows/reusable-workflow-guard.yml',...sharedManifests.filter(name=>name!=='coordinator/source-manifest.json')].sort();
 need(JSON.stringify(Object.keys(shared.reference_changes).sort())===JSON.stringify(sharedReferenceFiles));
 for(const [name,change] of Object.entries({...shared.source_changes,...shared.reference_changes})){
  const entry=shared.workflow_changes[name]||shared.manifest_changes[name];
  need(entry&&change.before===entry.before&&change.after===entry.after&&Object.keys(change).sort().join(',')==='after,before');
 }

 const transitionFiles=[".github/workflows/ci-cd.yml",".github/workflows/host-app-wake-receiving.yml",".github/workflows/host-app-wake-source.yml",".github/workflows/installation-principal-data.yml",".github/workflows/installation-registry-transactions.yml",".github/workflows/native-proof-data-journal.yml",".github/workflows/native-proof-transcript.yml",".github/workflows/principal-possession-data.yml",".github/workflows/push-coordinator-source.yml",".github/workflows/reusable-workflow-guard.yml",".github/workflows/rich-delivery-adapter.yml",".github/workflows/rich-session-data-profile.yml",".github/workflows/surface-enrollment-source.yml",".github/workflows/watch-moment-alert-source.yml",".github/workflows/worker-do-registry-source.yml"];
 need(Object.keys(transition.workflow_changes).length===transitionFiles.length&&transitionFiles.every(name=>Object.hasOwn(transition.workflow_changes,name)));
 const oldGovernance='software-assurance-governance.yml@dd02d6470f061e6e755e6fb47ae5331c34f89875';
 const newGovernance='software-assurance-governance.yml@aabd5de46ae438478eb894707e5b1ea27aca8508';
 for(const name of transitionFiles){
  const text=sharedPrevious[name],change=transition.workflow_changes[name];
  need(text.split(newGovernance).length===2&&sha(Buffer.from(text))===change.after&&sha(Buffer.from(text.replace(newGovernance,oldGovernance)))===change.before);
 }
 need(Object.keys(transition.auxiliary_changes).length===1&&Object.hasOwn(transition.auxiliary_changes,'coordinator/source-manifest.json'));
 need(sha(Buffer.from(sharedPrevious['coordinator/source-manifest.json']))===transition.auxiliary_changes['coordinator/source-manifest.json'].after);
 for(const [name,pin] of Object.entries(root.source_hashes))if(!name.startsWith('node_modules/')){
  let expected=pin;
  if(Object.hasOwn(delta,name)){need(delta[name].before===expected);expected=delta[name].after;}
  if(Object.hasOwn(closed.changes,name)){need(closed.changes[name].before===expected);expected=closed.changes[name].after;}
  if(Object.hasOwn(retention.changes,name)){need(retention.changes[name].before===expected);expected=retention.changes[name].after;}
  if(Object.hasOwn(category.changes,name)){need(category.changes[name].before===expected);expected=category.changes[name].after;}
  if(Object.hasOwn(mount.changes,name)){need(mount.changes[name].before===expected);expected=mount.changes[name].after;}
  if(Object.hasOwn(dependency.source_changes,name)){need(dependency.source_changes[name].before===expected);expected=dependency.source_changes[name].after;}
  if(Object.hasOwn(watch.source_changes,name)){need(watch.source_changes[name].before===expected);expected=watch.source_changes[name].after;}
  if(Object.hasOwn(receipt.source_changes,name)){need(receipt.source_changes[name].before===expected);expected=receipt.source_changes[name].after;}
  if(Object.hasOwn(releaseRetention.changes,name)){need(releaseRetention.changes[name].before===expected);expected=releaseRetention.changes[name].after;}
  if(Object.hasOwn(bindings.changes,name)){need(bindings.changes[name].before===expected);expected=bindings.changes[name].after;}
  if(Object.hasOwn(toolchain.changes,name)){need(toolchain.changes[name].before===expected);expected=toolchain.changes[name].after;}
  if(Object.hasOwn(maintenance.changes,name)){need(maintenance.changes[name].before===expected);expected=maintenance.changes[name].after;}
  if(Object.hasOwn(stable.changes,name)){need(stable.changes[name].before===expected);expected=stable.changes[name].after;}
  if(Object.hasOwn(erasure.changes,name)){need(erasure.changes[name].before===expected);expected=erasure.changes[name].after;}
  if(Object.hasOwn(keyAddress.changes,name)){need(keyAddress.changes[name].before===expected);expected=keyAddress.changes[name].after;}
  if(Object.hasOwn(testFlight.changes,name)){need(testFlight.changes[name].before===expected);expected=testFlight.changes[name].after;}
  if(Object.hasOwn(publicTrial.source_changes,name)){need(publicTrial.source_changes[name].before===expected);expected=publicTrial.source_changes[name].after;}
  if(Object.hasOwn(alwaysOn.source_changes,name)){need(alwaysOn.source_changes[name].before===expected);expected=alwaysOn.source_changes[name].after;}
  if(Object.hasOwn(wrangler.changes,name)){need(wrangler.changes[name].before===expected);expected=wrangler.changes[name].after;}
  if(Object.hasOwn(governance.source_changes,name)){need(governance.source_changes[name].before===expected);expected=governance.source_changes[name].after;}
  if(Object.hasOwn(transition.source_changes,name)){need(transition.source_changes[name].before===expected);expected=transition.source_changes[name].after;}
  if(Object.hasOwn(shared.source_changes,name)){need(shared.source_changes[name].before===expected);expected=shared.source_changes[name].after;}
  if(Object.hasOwn(summary.workflow_changes,name)){need(summary.workflow_changes[name].before===expected);expected=summary.workflow_changes[name].after;}
  need(plan.source_hashes[name]===expected);
 }
 const pins={...root.source_hashes,...plan.source_hashes,...plan.reference_hashes};
 const installed=Object.keys(root.source_hashes).filter(p=>p.startsWith('node_modules/'));need(installed.length===50);
 for(const [name,change] of Object.entries(dependency.installed_changes)){need(name==='node_modules/pkijs/build/index.js'&&pins[name]===change.before);pins[name]=change.after;}
 await checkSourcePins(pins,repo);
 for(const p of toolFiles)pins[p]=sha(await readFile(join(repo,p)));
 const head=gitRead(['rev-parse','HEAD']);need(head.status===0&&/^[0-9a-f]{40}\n$/.test(head.stdout));
 return {head:head.stdout.trim(),pins};
}
export async function startLocalRuntime(){
 return startRuntime(false);
}
export async function startLocal40381Runtime(){
 return startRuntime(true);
}
async function startRuntime(private40381){
 const snapshot=await sourceSnapshot(),scratch=await mkdtemp(join(tmpdir(),'djc-native-local-'));await chmod(scratch,0o700);
 let runtime;
 try{
  const inputs=JSON.parse(await readFile(join(repo,'rendezvous-build-inputs.json')));
  const stage=private40381?await stage40381(snapshot,repo,scratch):undefined;
  const source=stage?.root??repo;
  const bridge=randomBytes(32).toString('base64url');
  const driver=`import {createProductRendezvousHandler} from ${JSON.stringify(join(source,'src/rendezvous/composition.ts'))};
export {RequestAdmission,AllocationBudget,AllocationIndex,EnrollmentCoordinator,BudgetedTransactionCoordinator} from ${JSON.stringify(join(source,'src/index.ts'))};
export default {async fetch(request,env){
 if(request.headers.get('X-Local-Bridge')!==env.LOCAL_BRIDGE)return new Response(null,{status:503});
 const path=new URL(request.url).pathname;
 if(!${JSON.stringify(ROUTES)}.includes(path)||request.method!=='POST')return new Response(null,{status:400});
 const headers=new Headers({'Content-Type':'application/json','CF-Connecting-IP':'192.0.2.20'});
 if(['/create','/poll','/consume','/cancel'].includes(path))headers.set('Origin','https://vibecast.tv');
 const incoming=new Request('https://api.djconnect.dev/v1/rendezvous'+path,{method:'POST',headers,body:request.body,cf:{colo:'AMS'}});
 return createProductRendezvousHandler(env)(incoming);
}};`;
  await writeFile(join(scratch,'driver.ts'),driver,{mode:0o600});
  const aliases=Object.fromEntries(Object.entries(inputs.aliases).map(([k,v])=>[k,resolve(source,v)]));
  if(stage)Object.assign(aliases,{cbor:join(repo,'node_modules/cbor/lib/cbor.js'),asn1js:createRequire(import.meta.url).resolve('asn1js'),pkijs:createRequire(import.meta.url).resolve('pkijs')});
  const config={name:'djc-private-native-local',main:join(scratch,'driver.ts'),compatibility_date:'2026-06-20',compatibility_flags:['nodejs_compat'],workers_dev:false,send_metrics:false,alias:aliases};
  await writeFile(join(scratch,'wrangler.json'),JSON.stringify(config),{mode:0o600});
  const built=spawnSync(process.execPath,[join(repo,'node_modules/wrangler/bin/wrangler.js'),'deploy','--dry-run','--config',join(scratch,'wrangler.json'),'--outdir',join(scratch,'build'),'--metafile',join(scratch,'meta.json')],{cwd:repo,encoding:'utf8',timeout:120000,env:{...process.env,WRANGLER_SEND_METRICS:'false'}});
  need(built.status===0); // Build output is deliberately never logged (paths/contents may be private).
  const bundle=await readFile(join(scratch,'build/driver.js'),'utf8');
  need(!bundle.includes('SoftwareEnrollment')&&!bundle.includes('SOFTWARE_STUB_COMPOSITION'));
  const metadata=JSON.parse(await readFile(join(scratch,'meta.json')));
  const entry=Object.values(metadata.outputs).find(o=>o.entryPoint);need(entry&&entry.exports.length===6&&entry.exports.includes('default'));
  if(stage){await stage.verify();check40381Graph(metadata,stage,snapshot,repo,scratch);}
  for(const p of Object.keys(metadata.inputs)){
   need(!/(?:-harness|\.check\.|fixtures|pre-qr-replacement-reference)/i.test(p));
   if(p.startsWith('node-built-in-modules:'))continue;
   const absolute=resolve(scratch,p);
   need(absolute===join(scratch,'driver.ts')||Object.hasOwn(snapshot.pins,absolute.slice(repo.length+1))&&absolute.startsWith(repo+'/')||stage&&absolute.startsWith(stage.root+'/')&&Object.hasOwn(stage.pins,absolute.slice(stage.root.length+1)));
  }
  const require=createRequire(import.meta.resolve('wrangler'));
  const {Miniflare,Log,LogLevel,convertV4MiniflareOptions}=require('miniflare');
  const until=Date.now()+900000;
  const bindings={LOCAL_BRIDGE:bridge,RENDEZVOUS_EDGE_POLICY:'djc-direct-edge-identity/1-candidate',RENDEZVOUS_IP_HASH_KEY:randomBytes(32).toString('base64'),RECEIPT_ACTIVE_KEY:randomBytes(32).toString('base64'),COMPOSED_POLICY_ENABLED:'djc-http-composition-qualification/1',REQUEST_POLICY_ENABLED:'djc-request-admission-qualification/2',ALLOCATION_POLICY_ENABLED:'djc-allocation-qualification/1',INDEX_POLICY_ENABLED:'djc-index-qualification/1',ASSERTION_POLICY_ENABLED:'ios-dev-qualification/1',ASSERTION_POLICY_EXPIRES_AT:String(until),ENROLLMENT_POLICY_REVISION:stage?'private-40381-registration-recover/1':'local-native-file-experiment/1'};
  const egress={allowed:0,denied:0};
  const outbound=async request=>{egress[allowedStatusRequest(request)?'allowed':'denied']++;return statusOnlyOutbound(request);};
  runtime=new Miniflare({...convertV4MiniflareOptions({host:'127.0.0.1',inspectorHost:'127.0.0.1',durableObjectsPersist:false,unsafeInspectDurableObjects:true,log:new Log(LogLevel.NONE),workers:[{name:'local-native',compatibilityDate:'2026-06-20',compatibilityFlags:['nodejs_compat'],modulesRoot:join(scratch,'build'),modules:[{type:'ESModule',path:join(scratch,'build/driver.mjs'),contents:bundle}],bindings,durableObjects:Object.fromEntries(Object.entries(inputs.local_test_bindings).map(([k,className])=>[k,{className,useSQLite:true}])),outboundService:outbound},
   // Separate QA-only positive interception control; no DOs, secrets or arbitrary URL.
   {name:'guard-control',modulesRoot:scratch,modules:[{type:'ESModule',path:join(scratch,'guard.mjs'),contents:"export default {fetch(){return fetch('https://egress-denied.example.invalid/qualification');}}"}],outboundService:outbound}]}),enableDevRegistry:false});
  const url=await runtime.ready;need(url.hostname==='127.0.0.1');
  let inspectorDisabled=false;try{await runtime.getInspectorURL();}catch{inspectorDisabled=true;}need(inspectorDisabled);
  const control=await runtime.getWorker('guard-control');need((await control.fetch('https://local.invalid/')).status===503&&egress.denied===1&&egress.allowed===0);
  egress.denied=0;
  const worker=await runtime.getWorker('local-native');
  need((await worker.fetch('https://local.invalid/attestation/challenge',{method:'POST',body:'{}'})).status===503);
  need((await fetch(new URL('/attestation/challenge',url),{method:'POST',body:'{}',redirect:'manual'})).status===503);
  const send=(route,body)=>worker.fetch('https://local.invalid'+route,{method:'POST',headers:{'X-Local-Bridge':bridge},body});
  const request=stage?registrationRecoverController(send):send;
  return {
   snapshot,bundle_sha256:sha(bundle),
   ...(stage?{private_profile:{...stage.receipt,metafile_sha256:sha(JSON.stringify(metadata))}}:{}),
   egressObservation(){return {...egress};},
   async verifySources(){need(JSON.stringify(await sourceSnapshot())===JSON.stringify(snapshot));if(stage)await stage.verify();need(Date.now()<until);},
   async request(route,body){need(ROUTES.includes(route)&&body instanceof Uint8Array);if(stage){need(Date.now()<until);await stage.verify();}return request(route,body);},
   // Host-only observations, never RPC or wire parameters. Used by negative CI tests.
   async enrollmentObservation(keyId){
    const address=sha(JSON.stringify(['development','ios-dev-qualification/1',keyId]));
    const storage=await runtime.unsafeGetDurableObjectStorage('local-native','EnrollmentCoordinator',{name:'djc-rendezvous-key/1/'+address});
    return {keys:await storage.exec('SELECT COUNT(*) AS n FROM key_state'),operations:await storage.exec('SELECT expires_at,value FROM enrollment_operation')};
   },
   async stop(){await runtime.dispose();await rm(scratch,{recursive:true,force:true});},
  };
 }catch(error){if(runtime)await runtime.dispose();await rm(scratch,{recursive:true,force:true});throw error;}
}
