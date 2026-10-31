import {createProductionCoordinator} from './executor';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
export {createProductionCoordinator,SourceContainerExecutor,syntheticAdmission} from './executor';
export {SourceStateClient} from './rpc';
if(process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { createProductionCoordinator(); }
  catch {
    // No secret/env reads, key material, SDK, port, DB file or network call.
    process.stderr.write('coordinator unavailable: source qualification only\n');
    process.exitCode=78;
  }
}
