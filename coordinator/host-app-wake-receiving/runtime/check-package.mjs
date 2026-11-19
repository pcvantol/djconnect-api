import {resolve} from 'node:path';
import {verifyPackage} from './package-lib.mjs';
const proof=await verifyPackage(resolve(process.argv[2]),process.argv[3]);
console.log(JSON.stringify({actual_exact_package_files:Object.keys(proof.files_sha256).length+1,source_and_graph_integrity:true,public_activation:false,genuine_native_qualification:false}));
