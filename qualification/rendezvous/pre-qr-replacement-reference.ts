// API-owned contract reference ONLY. Not a receiver SDK, public router or timer.
export const CREATE_RECOVERY_POLICY='djc-pre-qr-replacement/1-draft';
export type CreateTicket=Readonly<{epoch:number;attempt:number;generation:number}>;
type Phase='idle'|'preparing'|'sending'|'reading'|'exposed'|'stopped';
export class PreQrReplacementReference {
  #clock:()=>number;#retired:(ticket:CreateTicket)=>void;#start:number;#last:number;
  #phase:Phase='idle';#active:CreateTicket|null=null;#epoch=0;#attempt=0;#posts=0;
  #deadline=0;#base:number;#exposed=false;#lost=false;#spent=false;
  #previous:{key:string;claim:string}|null=null;
  constructor(clock:()=>number=()=>performance.now(),retired:(ticket:CreateTicket)=>void=()=>{},generation=1){
    const now=clock();if(!Number.isFinite(now)||now<0||!Number.isInteger(generation)||generation<1||generation>=2147483647)throw new Error('invalid_reference_context');
    this.#clock=clock;this.#retired=retired;this.#start=now;this.#last=now;this.#base=generation;
  }
  snapshot(){return {phase:this.#phase,attempt:this.#attempt,post_starts:this.#posts,replacement_spent:this.#spent,ever_exposed:this.#exposed,context_lost:this.#lost};}
  #retire(){const old=this.#active;this.#active=null;this.#phase='stopped';this.#epoch++;if(old)try{this.#retired(old);}catch{this.#lost=true;}}
  #now(){if(this.#lost)return null;let now:number;try{now=this.#clock();}catch{this.#lost=true;this.#retire();return null;}if(!Number.isFinite(now)||now<this.#last||now-this.#start>=30000){this.#lost=true;this.#retire();return null;}this.#last=now;return now;}
  #current(ticket:CreateTicket){return this.#active===ticket&&!this.#lost;}
  #live(ticket:CreateTicket){if(!this.#current(ticket))return false;const now=this.#now();return now!==null&&this.#current(ticket)&&now<this.#deadline;}
  #prepare(now:number){this.#attempt++;const ticket=Object.freeze({epoch:++this.#epoch,attempt:this.#attempt,generation:this.#base+this.#attempt-1});this.#active=ticket;this.#phase='preparing';this.#deadline=now+5000;return ticket;}
  start(){if(this.#phase!=='idle'||this.#attempt!==0||this.#lost)return null;const now=this.#now();return now===null?null:this.#prepare(now);}
  // Fingerprints only: caller owns actual fresh WebCrypto key/claim generation and
  // must fence every continuation and discard its own references on retirement.
  prepared(ticket:CreateTicket,key:string,claim:string){
    if(this.#phase!=='preparing'||!this.#live(ticket))return false;
    const opaque=(v:string)=>typeof v==='string'&&/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(v);
    if(!opaque(key)||!opaque(claim)||this.#previous&&(key===this.#previous.key||claim===this.#previous.claim)){this.#retire();return false;}
    this.#previous={key,claim};this.#phase='sending';this.#deadline=this.#last+10000;this.#posts++;return true;
  }
  headers(ticket:CreateTicket,status:number){
    if(this.#phase!=='sending'||!this.#current(ticket))return false;
    // Known denial wins even at/after local deadlines; late headers must never
    // leave an eligible attempt for a following timeout/body-failure callback.
    if(status!==201){this.#retire();return false;}
    if(!this.#live(ticket))return false;
    this.#phase='reading';return true;
  }
  #replace(ticket:CreateTicket){
    if(!this.#current(ticket)||!['sending','reading'].includes(this.#phase)||this.#exposed)return null;
    const canReplace=this.#attempt===1&&!this.#spent&&this.#posts===1;
    if(canReplace)this.#spent=true;
    this.#retire(); // Fence FIRST, then best-effort caller abort/reference disposal.
    if(!canReplace||this.#lost)return null;
    const now=this.#now();return now===null?null:this.#prepare(now);
  }
  transportFailure(ticket:CreateTicket){if(!['sending','reading'].includes(this.#phase)||!this.#current(ticket)||this.#now()===null)return null;return this.#replace(ticket);}
  timeout(ticket:CreateTicket){
    if(!['preparing','sending','reading'].includes(this.#phase)||!this.#current(ticket))return null;const now=this.#now();if(now===null||now<this.#deadline)return null;
    if(this.#phase==='preparing'){this.#retire();return null;}
    return this.#replace(ticket);
  }
  invalidResponse(ticket:CreateTicket){if(this.#phase==='reading'&&this.#current(ticket))this.#retire();}
  expose(ticket:CreateTicket,validate:()=>boolean,render:()=>void){
    if(this.#phase!=='reading'||!this.#live(ticket))return false;
    let valid=false;try{valid=validate()===true;}catch{valid=false;}
    if(this.#phase!=='reading'||!this.#live(ticket))return false;
    if(!valid){this.#retire();return false;}
    // Acceptance is sticky before ANY caller rendering/accessibility callback.
    this.#exposed=true;this.#phase='exposed';
    try{render();}catch{/* Never turn partial exposure into replacement authority. */}
    return true;
  }
  contextLost(){this.#lost=true;this.#retire();}
}
