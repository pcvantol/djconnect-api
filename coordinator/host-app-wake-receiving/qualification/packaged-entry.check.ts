import {describe,it,expect} from 'vitest';
import shipped,{createReceivingService} from 'djc-shipped-receiving';
import {createReceivingService as selectedByOrdinaryTests} from '../service';
describe('actual shipped receiving entry; no positive public admission',()=>{
 it('makes the ordinary HTTP tests use the identical packaged factory',()=>{expect(selectedByOrdinaryTests).toBe(createReceivingService);});
 it.each(['issuer/issue','issuer/status','issuer/withdraw','native/challenge','native/complete','native/status','authorization/resolve','operator/authorize','operator/withdraw','operator/native-policy','operator/native-policy/withdraw','register','wake','status','revoke'])('keeps packaged public entry unavailable for %s',async path=>{expect((await shipped.fetch(new Request('https://local.test/v1/push/host-app-wake/'+path,{method:'POST'}))).status).toBe(503);});
});
