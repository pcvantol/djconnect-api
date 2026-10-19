// LOCAL CORS TRANSPORT PROBE ONLY. No transaction/authority or production export.
import {createIngress} from './http-ingress';
const V='djc-rendezvous/1';
const handler=createIngress({enabled:()=>true,beforeBody:async()=>({ok:true}),admit:async()=>({ok:true}),dispatch:async route=>{
  if(route==='/poll')return {status:200,body:{v:V,state:'pending',expires_at:Date.now()+120000,retry_after_ms:2000}};
  if(route==='/cancel')return {status:200,body:{v:V,state:'cancelled'}};
  return {status:409,body:{v:V,error:'not_ready'}};
}});
export default {fetch:handler};
