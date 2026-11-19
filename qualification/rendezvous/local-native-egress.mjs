// Host-side guard for the actual local workerd outboundService, not a fake status provider.
const tuples=new Map([
 ['http://crl.apple.com/applerootcag3.crl',['GET','application/pkix-crl']],
 ['http://ocsp.apple.com/ocsp03-applerootcag3',['POST','application/ocsp-response']],
 ['http://ocsp.apple.com/ocsp03-aaica5g101',['POST','application/ocsp-response']],
]);
export function allowedStatusRequest(request){
 const tuple=tuples.get(request.url);
 return !!tuple&&request.method===tuple[0]&&request.headers.get('accept')===tuple[1]&&
  [...request.headers.keys()].every(k=>['accept','content-type','content-length'].includes(k))&&
  (request.method==='GET'?!request.body:request.headers.get('content-type')==='application/ocsp-request');
}
export async function statusOnlyOutbound(request){
 if(!allowedStatusRequest(request))return new Response(null,{status:503});
 const abort=new AbortController(),timer=setTimeout(()=>abort.abort(),4000);
 try{
  const body=request.method==='POST'?new Uint8Array(await request.arrayBuffer()):undefined;
  if(body&&(!body.length||body.length>4096))return new Response(null,{status:503});
  const response=await fetch(request.url,{method:request.method,headers:{accept:request.headers.get('accept'),...(body?{'content-type':'application/ocsp-request'}:{})},body,redirect:'manual',signal:abort.signal});
  if(response.status!==200)return new Response(null,{status:503});
  const reader=response.body?.getReader();if(!reader)return new Response(null,{status:503});
  const chunks=[];let length=0;
  for(;;){const {done,value}=await reader.read();if(done)break;length+=value.length;if(length>65536){await reader.cancel();return new Response(null,{status:503});}chunks.push(value);}
  if(!length)return new Response(null,{status:503});
  return new Response(Buffer.concat(chunks),{status:200,headers:{'content-type':response.headers.get('content-type')??'application/octet-stream'}});
 }catch{return new Response(null,{status:503});}finally{clearTimeout(timer);}
}
