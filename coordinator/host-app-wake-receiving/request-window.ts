/** One original request window, captured before body/auth/SQL/crypto awaits.
 * The clock supplier is mandatory. This class does not qualify that clock. */
import {integer,need,WakeError} from '../host-app-wake/wire';
export class RequestWindow {
 readonly capturedAt:number;readonly expiresAt:number;readonly signal:AbortSignal;
 private last:number;private readonly lifetime=new AbortController();private readonly timer:ReturnType<typeof setTimeout>;
 constructor(private readonly now:()=>number,signal:AbortSignal,originalCapture?:number){
  need(typeof now==='function'&&signal instanceof AbortSignal,'host_wake_clock_required',503);
  const observed=now();integer(observed);const at=originalCapture??observed;integer(at);integer(at+30000);need(observed>=at,'host_wake_clock_regressed',503);this.capturedAt=at;this.last=observed;this.expiresAt=at+30000;
  this.timer=setTimeout(()=>this.lifetime.abort(),Math.max(1,this.expiresAt-observed));this.signal=AbortSignal.any([signal,this.lifetime.signal]);
  try{this.check();}catch(e){this.close();throw e;}
 }
 check():number{
  need(!this.signal.aborted,'host_wake_cancelled',409);const at=this.now();integer(at);
  need(at>=this.last,'host_wake_clock_regressed',503);this.last=at;need(at<this.expiresAt,'host_wake_transport_expired',409);return at;
 }
 close(){clearTimeout(this.timer);this.lifetime.abort();}
 /** Every caller must still check before starting its next side effect. This
  * settles promptly if a body/crypto provider ignores cancellation; it does not
  * claim to cancel an already started SQL write or HTTP delivery. */
 async run<T>(work:()=>Promise<T>,stageSignal?:AbortSignal):Promise<T>{
  this.check();const signal=stageSignal?AbortSignal.any([this.signal,stageSignal]):this.signal;need(!signal.aborted,'host_wake_cancelled',409);const pending=work();let listener:()=>void=()=>{};
  const aborted=new Promise<never>((_,reject)=>{listener=()=>reject(new WakeError('host_wake_cancelled',409));signal.addEventListener('abort',listener,{once:true});if(signal.aborted)listener();});
  try{const value=await Promise.race([pending,aborted]);this.check();return value;}
  finally{signal.removeEventListener('abort',listener);}
 }
}
