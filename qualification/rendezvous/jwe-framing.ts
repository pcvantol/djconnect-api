// SHARED CANDIDATE INTERNAL: compiled product auth remains disabled; no native/production acceptance.
export interface BrowserPublicJwk {kty:'RSA';e:'AQAB';n:string}
const need:(value:unknown)=>asserts value=value=>{if(!value)throw new Error('framing_rejected');};
const encode=(bytes:Uint8Array)=>btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
function decode(value:unknown,min:number,max:number):Uint8Array {
  need(typeof value==='string'&&value.length>0&&value.length<=Math.ceil(max*4/3)&&/^[A-Za-z0-9_-]+$/.test(value));
  const bytes=Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));
  need(bytes.length>=min&&bytes.length<=max&&encode(bytes)===value);return bytes;
}
const digest=async(value:string)=>encode(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))));

// Fixed object-of-strings grammar, not a general JSON parser. JSON.parse decodes each
// string; the Map detects duplicate decoded names before any object assignment.
function headerStrings(text:string):Map<string,string> {
  let position=0;
  const space=()=>{while(position<text.length&&/[ \t\r\n]/.test(text[position]))position++;};
  const character=(expected:string)=>{space();need(text[position]===expected);position++;};
  const string=()=>{
    space();need(text[position]==='"');const start=position++;
    while(position<text.length){
      const c=text[position++];
      if(c==='"'){const value:unknown=JSON.parse(text.slice(start,position));need(typeof value==='string');return value;}
      if(c==='\\')position++; // JSON.parse checks escapes/control chars, including truncated ones.
    }
    throw new Error('framing_rejected');
  };
  const values=new Map<string,string>(),allowed=new Set(['alg','enc','typ','kid']);
  character('{');
  while(true){
    const key=string();need(allowed.has(key)&&!values.has(key));character(':');values.set(key,string());
    space();if(text[position]==='}'){position++;break;}character(',');
  }
  space();need(position===text.length&&values.size===4);return values;
}

export async function qualifyBrowserPublicJwk(input:unknown){
  try{
    need(input!==null&&typeof input==='object'&&!Array.isArray(input));
    need(Object.keys(input).sort().join(',')==='e,kty,n');
    const source=input as Record<string,unknown>,kty=source.kty,e=source.e,n=source.n;
    need(kty==='RSA'&&e==='AQAB'&&typeof n==='string');const modulus=decode(n,256,256);
    need((modulus[0]&128)!==0&&(modulus[255]&1)===1);
    const jwk:BrowserPublicJwk={kty,e,n};
    const thumbprint=await digest(JSON.stringify({e,kty,n}));
    return {ok:true as const,jwk,thumbprint};
  }catch{return {ok:false as const,error:'public_key_rejected' as const};}
}

export async function qualifyCompactJwe(input:unknown,expectedThumbprint:unknown){
  try{
    need(typeof input==='string'&&input.length>0&&input.length<=8192&&/^[A-Za-z0-9_.-]+$/.test(input));
    decode(expectedThumbprint,32,32);const parts=input.split('.');need(parts.length===5);
    const protectedBytes=decode(parts[0],1,8192);
    const fields=headerStrings(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(protectedBytes));
    need(fields.get('alg')==='RSA-OAEP-256'&&fields.get('enc')==='A256GCM'&&fields.get('typ')==='djc-rendezvous-destination+jwe'&&fields.get('kid')===expectedThumbprint);
    decode(parts[1],256,256);decode(parts[2],12,12);const ciphertext=decode(parts[3],1,2048);decode(parts[4],16,16);
    // Digest the exact original ASCII bytes. Header spacing/order/escapes are not normalized.
    const envelopeDigest=await digest(input);
    return {ok:true as const,envelopeDigest,ciphertextBytes:ciphertext.length};
  }catch{return {ok:false as const,error:'envelope_rejected' as const};}
}
