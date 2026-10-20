import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {deriveRootDispatcher} from './root-integration-runtime.mjs';

test('only the fixed source activation guard can be derived, never changed or ambiguous input',async()=>{
 const source=await readFile(new URL('../../src/rendezvous/dispatch.ts',import.meta.url),'utf8');
 const derived=deriveRootDispatcher(source);
 assert.equal(derived.replace('const PRODUCT_RENDEZVOUS_ENABLED = true as boolean;','const PRODUCT_RENDEZVOUS_ENABLED = false as boolean;'),source);
 for(const invalid of [derived,source.replace('false as boolean','Boolean(env.ENABLED)'),source+source,source.replace('const PRODUCT_RENDEZVOUS_ENABLED','const RENAMED')])assert.throws(()=>deriveRootDispatcher(invalid));
});
