/** Compiled rich successor DATA only. No live profile map, owner, clock or provider. */
export const PROFILE='djconnect-session-rich-v1' as const;
export const CONTRACT_SHA256='2a4a4a4f49e0f6d5a1015169ff63b27091f80d6d857423940a0381d955bbb499' as const;
export class RichDataError extends Error {
  constructor(readonly code:'invalid_data'|'byte_limit'|'ineligible_shape'='invalid_data'){super('rich_session_'+code);}
}
function need(ok:unknown,code:RichDataError['code']='invalid_data'):asserts ok {if(!ok)throw new RichDataError(code);}
const encoder=new TextEncoder();
function unicode(text:string){for(let n=0;n<text.length;n++){const c=text.charCodeAt(n);if(c>=0xd800&&c<=0xdbff){const next=text.charCodeAt(++n);need(next>=0xdc00&&next<=0xdfff);}else need(c<0xdc00||c>0xdfff);}}
function utf8(text:string):number {unicode(text);return encoder.encode(text).length;}
function integer(x:unknown,min=0):asserts x is number {need(typeof x==='number'&&Number.isSafeInteger(x)&&!Object.is(x,-0)&&x>=min);}
function finite(x:unknown):asserts x is number {need(typeof x==='number'&&Number.isFinite(x));}
function object(x:unknown):asserts x is Record<string,unknown>{need(x!==null&&typeof x==='object'&&!Array.isArray(x));}
function fields(x:unknown,required:readonly string[],optional:readonly string[]=[]):asserts x is Record<string,unknown>{object(x);need(required.every(k=>Object.hasOwn(x,k))&&Object.keys(x).every(k=>required.includes(k)||optional.includes(k)));}
function str(x:unknown,max:number,empty=false):asserts x is string {need(typeof x==='string'&&(empty||x.length>0)&&!x.includes('\0'));unicode(x);need(Array.from(x).length<=max);}
function identifier(x:unknown){str(x,128);need(/^[A-Za-z0-9_-]+$/.test(x));}
function map(x:unknown,empty=false){object(x);const entries=Object.entries(x);need((empty||entries.length>0)&&entries.length<=8);for(const [k,v]of entries){str(k,64);str(v,1024);}}
function https(x:unknown){str(x,2048);need(utf8(x)<=2048);let url:URL;try{url=new URL(x);}catch{throw new RichDataError();}need(url.protocol==='https:'&&url.hostname.length>0&&!url.username&&!url.password);}
interface Parsed {value:Record<string,unknown>;spans:WeakMap<object,{start:number;end:number}>}
/** Bounded strict parser with exact object spans. It never reserializes a received fragment. */
function parse(text:string,maxBytes:number):Parsed {
  need(typeof text==='string'&&text.length<=maxBytes,'byte_limit');need(utf8(text)<=maxBytes,'byte_limit');need(text.charCodeAt(0)!==0xfeff);
  let at=0,tokens=0;const spans=new WeakMap<object,{start:number;end:number}>();
  const ws=()=>{while(/[\x20\t\r\n]/.test(text[at]??'x'))at++;};
  const token=()=>need(++tokens<=512,'byte_limit');
  const string=():string=>{need(text[at]==='"');const start=at++;let end=false;
    while(at<text.length){const c=text[at++];if(c==='\\'){need(at<text.length);const e=text[at++];if(e==='u'){need(/^[a-fA-F0-9]{4}$/.test(text.slice(at,at+4)));at+=4;}else need('"\\/bfnrt'.includes(e));}
      else if(c==='"'){end=true;break;}else need(c.charCodeAt(0)>=32);}
    need(end);let s:string;try{s=JSON.parse(text.slice(start,at)) as string;}catch{throw new RichDataError();}unicode(s);return s;};
  const value=(depth:number):unknown=>{need(depth<=8,'byte_limit');ws();token();const start=at,c=text[at];
    if(c==='"')return string();
    if(c==='{'){at++;ws();const result:Record<string,unknown>=Object.create(null);
      if(text[at]!=='}')while(true){ws();token();const key=string();need(!Object.hasOwn(result,key));ws();need(text[at++]===':');result[key]=value(depth+1);ws();const end=text[at++];if(end==='}')break;need(end===',');}
      else at++;
      spans.set(result,{start,end:at});return result;
    }
    if(c==='['){at++;ws();const result:unknown[]=[];if(text[at]!==']')while(true){result.push(value(depth+1));ws();const end=text[at++];if(end===']')break;need(end===',');}else at++;return result;}
    const m=/^(?:-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null)/.exec(text.slice(at));need(m);at+=m[0].length;
    if(m[0]==='true')return true;if(m[0]==='false')return false;if(m[0]==='null')return null;const number=Number(m[0]);finite(number);return number;
  };
  const result=value(0);ws();need(at===text.length);object(result);return{value:result,spans};
}
function decode64(input:unknown):string {
  need(typeof input==='string'&&input.length>0&&input.length<=5462,'byte_limit');need(/^[A-Za-z0-9_-]+$/.test(input));
  let raw:string;try{raw=atob(input.replaceAll('-','+').replaceAll('_','/'));}catch{throw new RichDataError();}
  need(raw.length<=4096,'byte_limit');need(btoa(raw).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')===input);
  try{return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Uint8Array.from(raw,c=>c.charCodeAt(0)));}catch{throw new RichDataError();}
}
function deepFreeze(x:Record<string,unknown>):Readonly<Record<string,unknown>> {for(const v of Object.values(x))if(v&&typeof v==='object')deepFreeze(v as Record<string,unknown>);return Object.freeze(x);}
// Foundation dates stay numbers/bytes, never replaced by internal relay UTC integers.
function iso(x:unknown):number {str(x,128);need(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(x));const match=/^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|([+-])(\d\d):(\d\d))$/.exec(x)!;const [year,month,day,hour,minute,second]=match.slice(1,7).map(Number);const leap=year%4===0&&(year%100!==0||year%400===0);need(month>=1&&month<=12&&day>=1&&day<=[31,leap?29:28,31,30,31,30,31,31,30,31,30,31][month-1]&&hour<24&&minute<60&&second<60);if(match[7]!=='Z')need(Number(match[9])<24&&Number(match[10])<60);const n=Date.parse(x)/1000;finite(n);return n;}
function interval(start:unknown,end:unknown){const a=iso(start),b=iso(end);need(b>a&&b-a<=120.001);return {start:a,end:b};}
function contribution(x:unknown){fields(x,['moment_id','published_at','text','persona','source_attribution','usage_basis','expires_at']);identifier(x.moment_id);str(x.text,640);
  need(['home_dj','radio_dj','club_dj','festival_dj'].includes(x.persona as string));need(['cc0_facts_authored_expression','runtime_authored_direction','public_artist_narration_v1'].includes(x.usage_basis as string));map(x.source_attribution,x.usage_basis==='runtime_authored_direction');return interval(x.published_at,x.expires_at);}
function nowPlaying(x:unknown){fields(x,['item_id','subject_uri','track','artist','album','observed_at','expires_at','source_url','attribution','usage_basis']);identifier(x.item_id);
  need(typeof x.subject_uri==='string'&&/^spotify:track:[A-Za-z0-9]{22}$/.test(x.subject_uri));str(x.track,640);str(x.artist,256,true);str(x.album,256,true);https(x.source_url);map(x.attribution);need(x.usage_basis==='spotify_temporary_passive_metadata');return interval(x.observed_at,x.expires_at);}
interface Contents {attributes:Readonly<Record<string,unknown>>;state:Readonly<Record<string,unknown>>;attributesText:string;stateText:string;richBytes:number;richEligibleShape:boolean}
function contents(attributesText:string,stateText:string):Contents {
  const a=parse(attributesText,4096),s=parse(stateText,4096);need(utf8(attributesText)+utf8(stateText)<=4096,'byte_limit');fields(a.value,['presentationID']);need(typeof a.value.presentationID==='string');unicode(a.value.presentationID);
  const state=s.value;fields(state,['observedAt','expiresAt'],['theme','rich']);finite(state.observedAt);finite(state.expiresAt);need(state.expiresAt>state.observedAt&&state.expiresAt-state.observedAt<=120);
  if(Object.hasOwn(state,'theme'))need(['brand','chill','groove','energy','party'].includes(state.theme as string));
  let richBytes=0,richEligibleShape=false;
  if(Object.hasOwn(state,'rich')){const rich=state.rich;fields(rich,['bindingID','generation','sequence','receivedAt','receivedUptime','expiresAt'],['contribution','nowPlaying','playbackState']);
    identifier(rich.bindingID);identifier(rich.generation);integer(rich.sequence);finite(rich.receivedAt);finite(rich.receivedUptime);finite(rich.expiresAt);need(rich.receivedUptime>=0&&rich.expiresAt>rich.receivedAt&&rich.expiresAt-rich.receivedAt<=120);
    need(state.expiresAt<=rich.expiresAt);if(Object.hasOwn(rich,'playbackState'))need(['idle','stopped','playing','paused'].includes(rich.playbackState as string));
    let count=0;
    if(Object.hasOwn(rich,'contribution')){contribution(rich.contribution);count++;}
    if(Object.hasOwn(rich,'nowPlaying')){nowPlaying(rich.nowPlaying);count++;}
    need(count>0,'ineligible_shape');const span=s.spans.get(rich)!;richBytes=utf8(stateText.slice(span.start,span.end));need(richBytes<=2800,'byte_limit');richEligibleShape=true;
  }
  return {attributes:deepFreeze(a.value),state:deepFreeze(state),attributesText,stateText,richBytes,richEligibleShape};
}
/** Exact rational projection of the supplied IEEE754 value; NOT a clock witness. */
function milliseconds(value:number,ceil:boolean):bigint {
  finite(value);const view=new DataView(new ArrayBuffer(8));view.setFloat64(0,value);const bits=view.getBigUint64(0);
  const exponent=Number((bits>>52n)&2047n),fraction=bits&((1n<<52n)-1n);
  let numerator=(exponent===0?fraction:(1n<<52n)+fraction)*1000n;
  const shift=(exponent===0?-1022:exponent-1023)-52;let denominator=1n;
  if(shift>=0)numerator<<=BigInt(shift);else denominator<<=BigInt(-shift);
  if(bits>>63n)numerator=-numerator;
  const whole=numerator/denominator,remainder=numerator%denominator;
  return whole+(remainder===0n?0n:ceil?(numerator>0n?1n:0n):(numerator<0n?-1n:0n));
}
export function projectOriginalUtcBoundsData(observedSeconds:number,expirySeconds:number){
  finite(observedSeconds);finite(expirySeconds);need(observedSeconds>=0&&!Object.is(observedSeconds,-0)&&expirySeconds>observedSeconds);
  const observed=milliseconds(observedSeconds,true),expiry=milliseconds(expirySeconds,false),max=BigInt(Number.MAX_SAFE_INTEGER);
  need(observed>=0n&&observed<expiry&&expiry<=max);
  return Object.freeze({classification:'CORE_UTC_PROJECTION_DATA_ONLY' as const,source_observed_at_ms:Number(observed),source_expires_at_ms:Number(expiry)});
}
export interface RichCarrierData {
  readonly classification:'RICH_SESSION_PROFILE_DATA_ONLY';readonly profile_id:typeof PROFILE;
  readonly attributes_utf8:string;readonly content_state_utf8:string;readonly source_observed_at_ms:number;readonly source_expires_at_ms:number;
  readonly rich_bytes:number;readonly attributes_and_state_bytes:number;readonly rich_shape:boolean;
  readonly attributes:Readonly<Record<string,unknown>>;readonly state:Readonly<Record<string,unknown>>;
}
const originals=new WeakMap<Readonly<RichCarrierData>,Contents>();
/** Shape/budget DATA only: never actual source/native rights or clock admission. */
export function decodeRichCarrier(text:unknown):Readonly<RichCarrierData>{
  need(typeof text==='string');const c=parse(text,16384).value;
  fields(c,['schema_version','profile_id','attributes_utf8_b64u','content_state_utf8_b64u','source_observed_at_ms','source_expires_at_ms']);need(c.schema_version===1&&c.profile_id===PROFILE);
  integer(c.source_observed_at_ms);integer(c.source_expires_at_ms);need(c.source_observed_at_ms<c.source_expires_at_ms);
  const body=contents(decode64(c.attributes_utf8_b64u),decode64(c.content_state_utf8_b64u));
  const result=Object.freeze({classification:'RICH_SESSION_PROFILE_DATA_ONLY' as const,profile_id:PROFILE,attributes_utf8:body.attributesText,content_state_utf8:body.stateText,
    source_observed_at_ms:c.source_observed_at_ms,source_expires_at_ms:c.source_expires_at_ms,rich_bytes:body.richBytes,
    attributes_and_state_bytes:utf8(body.attributesText)+utf8(body.stateText),rich_shape:body.richEligibleShape,attributes:body.attributes,state:body.state});
  originals.set(result,body);return result;
}
export interface OriginalRichData {readonly attributes_utf8:string;readonly content_state_utf8:string;readonly source_observed_at_ms:number;readonly source_expires_at_ms:number}
/** Original primitive DATA equality only; caller values do not create independent admission. */
export function checkOriginalRichData(data:Readonly<RichCarrierData>,expected:OriginalRichData):Readonly<RichCarrierData>{
  need(originals.has(data));need(expected!==null&&typeof expected==='object'&&(Object.getPrototypeOf(expected)===Object.prototype||Object.getPrototypeOf(expected)===null));
  const fields=['attributes_utf8','content_state_utf8','source_observed_at_ms','source_expires_at_ms'] as const;
  const descriptors=Object.getOwnPropertyDescriptors(expected);need(Reflect.ownKeys(descriptors).length===4);
  for(const k of fields){const d=descriptors[k];need(d&&Object.hasOwn(d,'value')&&d.value===data[k]);}
  return data;
}
export interface ApnsData {readonly classification:'RICH_SESSION_APNS_DATA_ONLY';readonly body_utf8:string;readonly body_bytes:number;readonly profile_id:typeof PROFILE}
/** Pure reference serialization; no provider, token, native owner, purpose or clock is admitted. */
export function prepareApnsData(data:Readonly<RichCarrierData>,event:'update'|'end',timestampMs:number,dismissalMs?:number):Readonly<ApnsData>{
  const original=originals.get(data);need(original&&original.richEligibleShape,'ineligible_shape');need(event==='update'||event==='end');integer(timestampMs);
  if(event==='end')integer(dismissalMs);else need(dismissalMs===undefined);
  const body='{"aps":{"timestamp":'+Math.floor(timestampMs/1000)+',"event":'+JSON.stringify(event)+',"content-state":'+original.stateText+',"stale-date":'+Math.floor(data.source_expires_at_ms/1000)+(event==='end'?',"dismissal-date":'+Math.floor(dismissalMs!/1000):'')+'}}';
  const size=utf8(body);need(size<=4096,'byte_limit');return Object.freeze({classification:'RICH_SESSION_APNS_DATA_ONLY',body_utf8:body,body_bytes:size,profile_id:PROFILE});
}
/** No live profile registration can be created by DATA or caller-supplied owner booleans. */
export function createProductionRichProfile(..._args:unknown[]):never {throw new Error('original rich owner/rights/native target/clock/provider admission unavailable');}
