// Fixed source entrypoint; no command/env/request profile or verifier selector.
import {runFileExperiment} from './run-local-native.mjs';
import {startLocal40381Runtime} from './local-native-runtime.mjs';
runFileExperiment(startLocal40381Runtime).catch(()=>{
 process.stderr.write('PRIVATE_40381_EXPERIMENT_STOPPED; files retained; no automatic retry\n');process.exitCode=1;
});
