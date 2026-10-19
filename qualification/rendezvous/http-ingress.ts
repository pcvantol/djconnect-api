// LOCAL QUALIFICATION ONLY. Transport validation does not supply sender/HA authority.
import contract from 'djc-wire-schema';
import {base64Url,base64Decode} from 'djc-existing-crypto';
import {type BudgetResult} from './allocation-budget';
const V='djc-rendezvous/1',ORIGIN='https://vibecast.tv',SERVICE='https://api.djconnect.dev';
const routes={
  '/create':{schema:'create',response:'create_response',limit:4096,status:201,browser:true},
  '/inspect':{schema:'inspect',response:'inspect_response',limit:1024,status:200,browser:false},
  '/attestation/challenge':{schema:'attestation_challenge',response:'attestation_challenge_response',limit:1024,status:200,browser:false},
  '/attestation/register':{schema:'attestation_register',response:'attestation_register_response',limit:65536,status:201,browser:false},
  '/submit-challenge':{schema:'submit_challenge',response:'submit_challenge_response',limit:1024,status:200,browser:false},
  '/submit':{schema:'submit',response:'submit_response',limit:32768,status:202,browser:false},
  '/poll':{schema:'poll',response:'poll_response',limit:1024,status:200,browser:true},
  '/consume':{schema:'consume',response:'consume_response',limit:1024,status:200,browser:true},
  '/cancel':{schema:'cancel',response:'cancel_response',limit:1024,status:200,browser:true},
  '/attestation/delete':{schema:'attestation_delete',response:'attestation_delete_response',limit:16384,status:200,browser:false},
  '/attestation/recover':{schema:'attestation_recover',response:'attestation_recover_response',limit:16384,status:200,browser:false},
} as const;
export type IngressRoute=keyof typeof routes;
export type WireObject=Record<string,unknown>;
type Schema={ [key:string]:unknown;$ref?:string;type?:string;const?:unknown;enum?:unknown[];oneOf?:Schema[];anyOf?:Schema[];required?:string[];properties?:Record<string,Schema>;pattern?:string;minimum?:number;maximum?:number;minLength?:number;maxLength?:number;additionalProperties?:boolean };
const root=contract as Schema&{$defs:Record<string,Schema>};
const supported=new Set(['$schema','$id','$comment','$defs','$ref','type','const','enum','oneOf','anyOf','required','properties','additionalProperties','pattern','minimum','maximum','minLength','maxLength']);
function check(schema:Schema,value:unknown,depth=0):boolean {
  if(depth>32||Object.keys(schema).some(k=>!supported.has(k)))return false;
  if(schema.$ref){if(!schema.$ref.startsWith('#/$defs/'))return false;const key=schema.$ref.slice(8);if(!Object.hasOwn(root.$defs,key)||!check(root.$defs[key],value,depth+1))return false;}
  if(schema.oneOf&&schema.oneOf.filter(s=>check(s,value,depth+1)).length!==1)return false;
  if(schema.anyOf&&!schema.anyOf.some(s=>check(s,value,depth+1)))return false;
  if(Object.hasOwn(schema,'const')&&value!==schema.const||schema.enum&&!schema.enum.includes(value))return false;
  if(schema.type==='object'){
    if(!value||typeof value!=='object'||Array.isArray(value))return false;const object=value as WireObject,properties=schema.properties??{};
    if(schema.required?.some(k=>!Object.hasOwn(object,k)))return false;
    for(const key of Object.keys(object)){if(!Object.hasOwn(properties,key)){if(schema.additionalProperties===false)return false;}else if(!check(properties[key],object[key],depth+1))return false;}
  }else if(schema.type==='integer'){if(typeof value!=='number'||!Number.isSafeInteger(value)||value<(schema.minimum??-Infinity)||value>(schema.maximum??Infinity))return false;}
  else if(schema.type==='string'){
    if(typeof value!=='string'||[...value].length<(schema.minLength??0)||[...value].length>(schema.maxLength??Infinity))return false;
    if(schema.pattern){const match=new RegExp(schema.pattern).exec(value);if(!match||match[0].length!==value.length)return false;}
  }else if(schema.type==='boolean'){if(typeof value!=='boolean')return false;}
  else if(schema.type!==undefined)return false;
  return true;
}
export function matchesWireSchema(name:string,value:unknown):boolean {try{return name==='$root'?check(root,value):Object.hasOwn(root.$defs,name)&&check(root.$defs[name],value);}catch{return false;}}
class Rejection extends Error {constructor(readonly code:string,readonly status:number){super('request_rejected');}}
const need:(v:unknown,code?:string,status?:number)=>asserts v=(v,code='invalid_request',status=400)=>{if(!v)throw new Rejection(code,status);};
function parseJsonObject(bytes:Uint8Array):WireObject {
  const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);let position=0,nodes=0;
  const space=()=>{while(position<text.length&&/[ \t\r\n]/.test(text[position]))position++;};
  const string=()=>{space();need(text[position]==='"');const start=position++;while(position<text.length){const c=text[position++];if(c==='"')return JSON.parse(text.slice(start,position)) as string;if(c==='\\')position++;}throw new Rejection('invalid_request',400);};
  const value=(depth:number):unknown=>{
    space();need(depth<=8&&++nodes<=256);
    if(text[position]==='"')return string();
    if(text[position]==='{'){
      position++;const result=Object.create(null) as WireObject;space();if(text[position]==='}'){position++;return result;}
      while(true){const key=string();need(!Object.hasOwn(result,key));space();need(text[position++]===':');const v=value(depth+1);Object.defineProperty(result,key,{value:v,enumerable:true});space();const c=text[position++];if(c==='}')return result;need(c===',');}
    }
    // Closed request shapes contain integer literals only, never arrays/bool/null.
    const numeric=/-?(?:0|[1-9][0-9]*)/y;numeric.lastIndex=position;const match=numeric.exec(text);need(match);position=numeric.lastIndex;const number=Number(match[0]);need(Number.isSafeInteger(number));return number;
  };
  const result=value(0);space();need(position===text.length&&result&&typeof result==='object'&&!Array.isArray(result));return result as WireObject;
}
export function parseWireJson(bytes:Uint8Array):WireObject {try{return parseJsonObject(bytes);}catch{throw new Rejection('invalid_request',400);}}
function canonicalInputs(body:WireObject){
  const url=(v:unknown,max:number,exact?:number)=>{need(typeof v==='string'&&v.length>0&&v.length%4!==1&&v.length<=Math.ceil(max*4/3)&&/^[A-Za-z0-9_-]+$/.test(v));const b=Uint8Array.from(atob(v.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));need(b.length<=max&&(exact===undefined||b.length===exact)&&base64Url(b.buffer)===v);return b;};
  for(const key of ['claim_commitment','claim_secret','qr_capability','challenge_id','envelope_digest'])if(Object.hasOwn(body,key))url(body[key],32,32);
  for(const [key,max] of [['client_data',2048],['assertion',4096],['attestation',32768]] as const)if(Object.hasOwn(body,key))url(body[key],max);
  if(Object.hasOwn(body,'key_id')){const v=body.key_id;need(typeof v==='string');const b=base64Decode(v);need(b.length===32&&btoa(String.fromCharCode(...b))===v);}
  if(Object.hasOwn(body,'browser_public_key')){const pub=body.browser_public_key as WireObject,b=url(pub.n,256,256);need((b[0]&128)!==0&&(b[255]&1)===1);}
  if(Object.hasOwn(body,'destination_envelope')){const parts=(body.destination_envelope as string).split('.');need(parts.length===5);url(parts[0],8192);url(parts[1],256,256);url(parts[2],12,12);url(parts[3],2048);url(parts[4],16,16);}
}
async function readBody(request:Request,limit:number):Promise<Uint8Array>{
  const length=request.headers.get('Content-Length');if(length!==null)need(/^(0|[1-9][0-9]*)$/.test(length)&&Number.isSafeInteger(Number(length))&&Number(length)<=limit,'payload_too_large',413);
  need(request.body);const reader=request.body.getReader(),chunks:Uint8Array[]=[],deadline=Date.now()+5000;let total=0,zeros=0;
  try{while(true){need(!request.signal.aborted);const left=deadline-Date.now();need(left>0,'service_unavailable',503);let timer:ReturnType<typeof setTimeout>|undefined;
      const next=await Promise.race([reader.read(),new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>reject(new Rejection('service_unavailable',503)),left);})]).finally(()=>{if(timer!==undefined)clearTimeout(timer);});
      need(!request.signal.aborted);need(Date.now()<deadline,'service_unavailable',503);
      if(next.done)break;need(next.value instanceof Uint8Array);total+=next.value.byteLength;need(total<=limit,'payload_too_large',413);if(next.value.length===0)need(++zeros<=8);else chunks.push(Uint8Array.from(next.value));
    }
    need(!request.signal.aborted);need(Date.now()<deadline,'service_unavailable',503);
    need(total>0&&(length===null||Number(length)===total));const result=new Uint8Array(total);let offset=0;for(const chunk of chunks){result.set(chunk,offset);offset+=chunk.length;}return result;
  }finally{void reader.cancel().catch(()=>{});reader.releaseLock();}
}
export interface IngressDependencies {beforeBody?:(route:IngressRoute)=>Promise<BudgetResult>;enabled:()=>boolean;admit:(route:IngressRoute,body:WireObject)=>Promise<BudgetResult>;dispatch:(route:IngressRoute,body:WireObject)=>Promise<{status:number;body:unknown}>}
const statuses:Record<string,number>={invalid_request:400,unsupported_version:400,invalid_capability:401,invalid_sender_proof:401,attestation_required:401,app_not_supported:403,origin_denied:403,operation_conflict:409,already_submitted:409,already_consumed:409,cancelled:409,not_ready:409,expired:410,payload_too_large:413,unsupported_content_type:415,rate_limited:429,attestation_unavailable:503,service_unavailable:503};
export function createIngress(dependencies?:IngressDependencies){
  return async(request:Request):Promise<Response>=>{
    const origin=request.headers.get('Origin'),headers=new Headers({'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Vary':'Origin'});if(origin===ORIGIN)headers.set('Access-Control-Allow-Origin',ORIGIN);
    const json=(body:unknown,status:number)=>{headers.set('Content-Type','application/json; charset=utf-8');return new Response(JSON.stringify(body),{status,headers});};
    const ready=()=>need(dependencies?.enabled(),'service_unavailable',503);
    const admitted=(admission:BudgetResult):Response|undefined=>{
      need(admission&&typeof admission==='object','service_unavailable',503);if(admission.ok===false){const code=admission.error;need(code==='rate_limited'||code==='service_unavailable','service_unavailable',503);const error={v:V,error:code,...(admission.retry_after_ms!==undefined?{retry_after_ms:admission.retry_after_ms}:{})};need(matchesWireSchema('error',error),'service_unavailable',503);if(error.retry_after_ms)headers.set('Retry-After',String(Math.ceil(error.retry_after_ms/1000)));return json(error,statuses[code]);}need(admission.ok===true&&Object.keys(admission).join(',')==='ok','service_unavailable',503);
      return undefined;
    };
    try{
      ready();const url=new URL(request.url),path=url.pathname.slice('/v1/rendezvous'.length);need(Object.hasOwn(routes,path)&&url.href===SERVICE+'/v1/rendezvous'+path);const route=path as IngressRoute,definition=routes[route];
      if(dependencies!.beforeBody){const response=admitted(await dependencies!.beforeBody(route));ready();if(response)return response;}
      need(origin===null||origin===ORIGIN,'origin_denied',403);need(!request.headers.has('Cookie')&&!request.headers.has('Authorization'),'invalid_request');
      if(request.method==='OPTIONS'){
        need(origin===ORIGIN&&request.headers.get('Access-Control-Request-Method')==='POST','origin_denied',403);const requested=request.headers.get('Access-Control-Request-Headers');need(requested===null||requested.trim().toLowerCase()==='content-type','origin_denied',403);
        headers.set('Access-Control-Allow-Methods','POST');headers.set('Access-Control-Allow-Headers','Content-Type');headers.set('Vary','Origin, Access-Control-Request-Method, Access-Control-Request-Headers');return new Response(null,{status:204,headers});
      }
      need(request.method==='POST');need(!definition.browser||origin===ORIGIN,'origin_denied',403);
      const contentType=request.headers.get('Content-Type')??'',match=/^application\/json(?:[ \t]*;[ \t]*charset=utf-8)?$/i.exec(contentType);need(match&&match[0].length===contentType.length,'unsupported_content_type',415);need(!request.headers.has('Content-Encoding'),'unsupported_content_type',415);
      const body=parseWireJson(await readBody(request,definition.limit));need(typeof body.v==='string');need(body.v===V,'unsupported_version');need(matchesWireSchema(definition.schema,body));canonicalInputs(body);ready();
      const admissionResponse=admitted(await dependencies!.admit(route,body));ready();if(admissionResponse)return admissionResponse;
      const result=await dependencies!.dispatch(route,body);ready();const output=structuredClone(result.body);
      if(result.status===definition.status){let response:string=definition.response;if(route==='/attestation/challenge')response=body.action==='register'?'attestation_register_challenge_response':'attestation_delete_challenge_response';need(matchesWireSchema(response,output),'service_unavailable',503);return json(output,definition.status);}
      need(matchesWireSchema('error',output),'service_unavailable',503);const error=output as {error:string;retry_after_ms?:number};need(statuses[error.error]===result.status,'service_unavailable',503);if(error.retry_after_ms)headers.set('Retry-After',String(Math.ceil(error.retry_after_ms/1000)));return json(output,result.status);
    }catch(error){return error instanceof Rejection?json({v:V,error:error.code},error.status):json({v:V,error:'service_unavailable'},503);}
  };
}
