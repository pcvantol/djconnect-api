import type {CoordinatorSourceState} from './state';
import {SOURCE,flat,fail,epochData,jobData,claimData,type Epoch,type Job,type Claim} from './model';

/** Concrete DO RPC client, not a replaceable SQL/store implementation. */
export class SourceStateClient {
  constructor(readonly stub:Pick<DurableObjectStub<CoordinatorSourceState>,'sourceCommand'>) {}
  /** Fixed private virtual host, intercepted by the owning DO. No Internet fallback. */
  static forContainer():SourceStateClient {
    return new SourceStateClient({async sourceCommand(wire:string):Promise<string> {
      const response=await fetch('http://coordinator.state/source-transaction',{
        method:'POST',headers:{'Content-Type':'application/json'},body:wire,redirect:'manual',
      });
      if(response.status!==200 || !response.body)fail('source state response unavailable');
      const reader=response.body.getReader();const parts:Uint8Array[]=[];let size=0;
      try {while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;
        if(size>2048)fail('source state response cap');parts.push(value);}}
      finally {await reader.cancel();}
      const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
      return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);
    }});
  }
  private async call(method:string,args:unknown[]):Promise<string|null> {
    const reply=await this.stub.sourceCommand(JSON.stringify({label:SOURCE,method,args}));
    if(typeof reply !== 'string' || reply.length>2048) fail('invalid source response');
    const data:unknown=JSON.parse(reply);
    const ok=Object.getOwnPropertyDescriptor(data as object,'ok')?.value;
    if(ok===false) { const e=flat(data,['ok','error']);if(typeof e.error!=='string')fail('invalid error response');fail(e.error as string); }
    const result=flat(data,['ok','value']);
    if(result.ok!==true || (result.value!==null && typeof result.value!=='string'))fail('invalid source response');
    return result.value as string|null;
  }
  async initializeSourceFixture(label:string,restore:string):Promise<string> {
    if(label!==SOURCE)fail('source fixture required');return this.text(await this.call('initialize',[restore]));
  }
  async advanceContainerGeneration(e:Epoch):Promise<string> {return this.text(await this.call('generation',[epochData(e)]));}
  async registerParentData(e:Epoch,j:Job):Promise<void> {this.empty(await this.call('parent',[epochData(e),jobData(j)]));}
  async createJobData(e:Epoch,j:Job,operation:string,nonce:string,maxJobs:number):Promise<void> {
    this.empty(await this.call('create',[epochData(e),jobData(j),operation,nonce,maxJobs]));
  }
  async commitStageData(e:Epoch,j:Job,c:Claim):Promise<string> {
    return this.text(await this.call('stage',[epochData(e),jobData(j),claimData(c)]));
  }
  async validateSpentData(e:Epoch,j:Job):Promise<void> {this.empty(await this.call('validate',[epochData(e),jobData(j)]));}
  async retireParentData(e:Epoch,parent:string):Promise<void> {this.empty(await this.call('retire',[epochData(e),parent]));}
  private text(value:string|null):string {if(typeof value!=='string')fail('missing ACK data');return value as string;}
  private empty(value:string|null):void {if(value!==null)fail('unexpected ACK data');}
}
