import {WorkerEntrypoint} from 'cloudflare:workers';
import type {CoordinatorSourceState} from './state';

interface SourceEnv { SOURCE_STATE:DurableObjectNamespace<CoordinatorSourceState> }
/** Only a DO-created loopback entrypoint may bind the own object ID in props.
 * No public route, body/header-selected ID, default fetch forwarding or provider hop.
 */
export class SourceStateOutbound extends WorkerEntrypoint<SourceEnv,{stateId:string}> {
  async fetch(request:Request):Promise<Response> {
    const url=new URL(request.url);
    if(url.href!=='http://coordinator.state/source-transaction' || request.method!=='POST'
      || request.headers.get('Content-Type')!=='application/json')return new Response(null,{status:403});
    if(!request.body)return new Response(null,{status:400});
    const reader=request.body.getReader();let size=0;const parts:Uint8Array[]=[];
    try {while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;
      if(size>16384)return new Response(null,{status:413});parts.push(value);}}
    finally {await reader.cancel();}
    const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
    let body:string;try{body=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{return new Response(null,{status:400});}
    const own=this.env.SOURCE_STATE.get(this.env.SOURCE_STATE.idFromString(this.ctx.props.stateId));
    return new Response(await own.sourceCommand(body),{headers:{'Content-Type':'application/json'}});
  }
}
