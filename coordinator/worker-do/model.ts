/** Private registry DATA model. Not a new normative client wire or registrar authority. */
import {canonical,parseStrictJson} from '../../src/surface-push/wire';
import {publicKey} from '../../src/surface-push/issuer-wire';
import {sha256Hex} from '../../src/crypto';
export const SOURCE='SOURCE_REGISTRY_DATA_ONLY_NOT_AUTHORITY' as const;
export function need(ok:unknown,message='invalid registry data'):asserts ok {if(!ok)throw new Error(message);}
export function closed(o:unknown,keys:readonly string[]):asserts o is Record<string,unknown> {
  need(!!o && typeof o==='object' && !Array.isArray(o));
  need(Object.keys(o).length===keys.length && keys.every(k=>Object.hasOwn(o,k)));
}
export function id(value:unknown):asserts value is string {need(typeof value==='string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value));}
export function hash(value:unknown):asserts value is string {need(typeof value==='string' && /^[a-f0-9]{64}$/.test(value));}
export function integer(value:unknown,min=1):asserts value is number {need(Number.isSafeInteger(value) && (value as number)>=min && (value as number)<Number.MAX_SAFE_INTEGER);}
export function operation(value:unknown):asserts value is string {need(typeof value==='string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value));}
export interface RegistryData {
  principal_id:string;principal_epoch:number;core_instance_id:string;installation_id:string;
  accepted_pair_binding_sha256:string;public_key_jwk_canonical:string;public_key_thumbprint:string;
  allowed_purposes:('paired-device-transport'|'paired-session-status-child')[];policy_sha256:string;
  registration_provenance_sha256:string;pop_receipt_sha256:string;original_permission_expires_at_unix_ms:number;
}
const FIELDS=['principal_id','principal_epoch','core_instance_id','installation_id','accepted_pair_binding_sha256',
  'public_key_jwk_canonical','public_key_thumbprint','allowed_purposes','policy_sha256','registration_provenance_sha256',
  'pop_receipt_sha256','original_permission_expires_at_unix_ms'] as const;
/** Only validates public bytes/hash/curve. Provenance/PoP hashes remain unverified DATA. */
export async function registryData(value:unknown):Promise<{record:RegistryData;body:string;digest:string}> {
  closed(value,FIELDS);id(value.principal_id);integer(value.principal_epoch);id(value.core_instance_id);id(value.installation_id);
  for(const key of ['accepted_pair_binding_sha256','public_key_thumbprint','policy_sha256','registration_provenance_sha256','pop_receipt_sha256'])hash(value[key]);
  integer(value.original_permission_expires_at_unix_ms);
  const purposes=['paired-device-transport','paired-session-status-child'];
  need(Array.isArray(value.allowed_purposes) && value.allowed_purposes.length>=1 && value.allowed_purposes.length<=2);
  need(value.allowed_purposes.every((p,i,a)=>purposes.includes(p) && (i===0 || purposes.indexOf(p)>purposes.indexOf(a[i-1]))),'invalid allowed purposes');
  need(typeof value.public_key_jwk_canonical==='string' && value.public_key_jwk_canonical.length<=512);
  const jwk=parseStrictJson(value.public_key_jwk_canonical);closed(jwk,['kty','crv','x','y']);
  need(jwk.kty==='EC' && jwk.crv==='P-256');need(canonical(jwk)===value.public_key_jwk_canonical,'noncanonical public JWK');
  await publicKey(jwk as {kty:'EC';crv:'P-256';x:string;y:string});
  need(await sha256Hex(value.public_key_jwk_canonical)===value.public_key_thumbprint,'public pin mismatch');
  const body=canonical(value);const record=JSON.parse(body) as RegistryData;
  return {record,body,digest:await sha256Hex(body)};
}
export {canonical,parseStrictJson};
