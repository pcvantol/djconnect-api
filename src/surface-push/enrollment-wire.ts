/** Closed source-only enrollment delegation, separate from push capability issuance. */
import { sha256Hex } from "../crypto";
import { canonical, need } from "./wire";
import { bytes, closed, enrolment, id, operationDeadline, ISSUER_VERSION, thumbprint, type Enrolment } from "./issuer-wire";
export const ENROLLMENT_DOMAIN = "djc-surface-enrollment/1";
export const ENROLLMENT_PREFIX = "/v1/push/surface/enrollment/";
export const REDEEM_PATH = ENROLLMENT_PREFIX + "redeem";
export interface Consent { nonce: string; action_id: string; generation_id: string; plan_digest: string; expires_at_ms: number }
export interface Authorization {
 contract_version: 1; purpose: "surface_enrollment"; action: "authorize";
 operation_id: string; authorization_id: string; consent: Consent; enrollment: Enrolment;
}
export interface Redemption {
 contract_version: 1; purpose: "surface_enrollment"; action: "redeem";
 authorization_id: string; consent: Consent; enrollment: Enrolment;
}
export function consent(value: unknown, now: number): Consent {
 closed(value,["nonce","action_id","generation_id","plan_digest","expires_at_ms"]);
 need(typeof value.nonce === "string"); bytes(value.nonce,32);
 id(value.action_id); id(value.generation_id);
 need(typeof value.plan_digest === "string" && /^[a-f0-9]{64}$/.test(value.plan_digest));
 need(Number.isSafeInteger(value.expires_at_ms) && (value.expires_at_ms as number)>now && (value.expires_at_ms as number)<=now+900000);
 return value as unknown as Consent;
}
export function widgetEnrollment(value: unknown, now: number): Enrolment {
 const v=enrolment(value,now,[]), p=v.policy;
 need(p.token_role==="widget" && p.activity_profile===null && !p.external_content_allowed,"surface_content_not_admitted",403);
 need(p.original_grant_expires_at_ms<=now+900000 && p.max_operations<=4 && p.max_events<=2 && p.max_challenges===1);
 return v;
}
export function authorize(value: unknown, now: number): Authorization {
 closed(value,["contract_version","purpose","action","operation_id","authorization_id","consent","enrollment"]);
 need(value.contract_version===1 && value.purpose==="surface_enrollment" && value.action==="authorize");
 id(value.authorization_id); need(typeof value.operation_id==="string"); operationDeadline(value.operation_id,now);
 consent(value.consent,now); widgetEnrollment(value.enrollment,now);
 need((value.enrollment as Enrolment).policy.original_grant_expires_at_ms <= (value.consent as Consent).expires_at_ms);
 return value as unknown as Authorization;
}
export function redeem(value: unknown, now: number): { payload: Redemption; signature: string } {
 closed(value,["payload","signature"]); need(typeof value.signature==="string"); bytes(value.signature,64);
 const p=value.payload; closed(p,["contract_version","purpose","action","authorization_id","consent","enrollment"]);
 need(p.contract_version===1 && p.purpose==="surface_enrollment" && p.action==="redeem"); id(p.authorization_id);
 consent(p.consent,now); widgetEnrollment(p.enrollment,now);
 need((p.enrollment as Enrolment).policy.original_grant_expires_at_ms <= (p.consent as Consent).expires_at_ms);
 return value as unknown as {payload:Redemption;signature:string};
}
export function redemptionBytes(value: Redemption): Uint8Array<ArrayBuffer> {
 return new Uint8Array(new TextEncoder().encode(canonical([ENROLLMENT_DOMAIN,"POST",REDEEM_PATH,value])));
}
export async function bindings(c: Consent, e: Enrolment) {
 const key=await thumbprint(e.public_key);
 return {
  nonce:await sha256Hex(c.nonce),
  action:await sha256Hex(canonical([ENROLLMENT_DOMAIN,"action",e.install_id,c.generation_id,c.action_id])),
  consent:await sha256Hex(canonical([ENROLLMENT_DOMAIN,"consent",c])),
  request:await sha256Hex(canonical([ISSUER_VERSION,"operator/enrol",e])),
  key,
  scope:await sha256Hex(canonical([ISSUER_VERSION,"delegation",e.delegation_id,1,e.install_id,e.device_binding,e.owner_binding,e.grant_binding,e.source_binding,e.binding_id,key,e.policy])),
 };
}
