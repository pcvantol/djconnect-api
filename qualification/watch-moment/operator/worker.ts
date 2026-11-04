import { DurableObject } from "cloudflare:workers";
import { WatchEnrollmentAuthority } from "../../../src/watch-lifecycle/enrollment-authority";
import { createWatchEnrollmentIssueHttp, createWatchEnrollmentRedeemHttp } from "../../../src/watch-lifecycle/enrollment-http";
import type { EnrollmentIntent } from "../../../src/watch-lifecycle/enrollment";

export class DispatchActor extends DurableObject<{DB: D1Database}> {
  private resume?: () => void;
  async fetch(req: Request) {
    const authority = new WatchEnrollmentAuthority(this.ctx.storage, "home");
    switch (new URL(req.url).pathname) {
      case "/authorize": return Response.json(await authority.authorize(await req.json<EnrollmentIntent>()));
      case "/revoke": return Response.json(await authority.revoke(await req.json<string>()));
      case "/admitted": return Response.json(authority.isAdmitted(await req.json<EnrollmentIntent>()));
      case "/ready": return Response.json(this.resume !== undefined);
      case "/resume": this.resume?.(); return Response.json(true);
      case "/issue": {
        const {intent,spki} = await req.clone().json<{intent:EnrollmentIntent;spki:number[]}>();
        return createWatchEnrollmentIssueHttp(this.env.DB, async () => ({
          intent,publicSpki:Uint8Array.from(spki),assertCurrent:value=>authority.assertCurrent(value),
        }))(req);
      }
      default: {
        const db = new Proxy(this.env.DB, {
          get:(target, prop) => prop !== "prepare" ? Reflect.get(target, prop, target) : (sql:string) => {
            const statement = target.prepare(sql);
            if (!sql.startsWith("UPDATE watch_lifecycle_enrollment SET consumed=1")) return statement;
            return {bind:(...values:unknown[])=>({first:async()=>{
              const row = await statement.bind(...values).first();
              await new Promise<void>(resolve => {this.resume=resolve;});
              return row;
            }})};
          },
        });
        return createWatchEnrollmentRedeemHttp(db, {assertCurrent:value=>authority.assertCurrent(value)})(req);
      }
    }
  }
}
export default {fetch:()=>new Response(null,{status:404})};
