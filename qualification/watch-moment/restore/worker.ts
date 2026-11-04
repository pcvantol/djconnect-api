import {createMomentTransport} from "../../../src/watch-moment/service";
import {createWatchRetirementHttp} from "../../../src/watch-lifecycle/retirement-http";
import {resolveWatchRetirementScope} from "../../../src/watch-lifecycle/registry-scope";
import {sha256Hex} from "../../../src/crypto";
import {canonical} from "../../../src/watch-moment/wire";
import {createRestoredWatchSender} from "../../../src/watch-lifecycle/restore-dispatch";
import {WatchDispatchFence} from "../../../src/watch-lifecycle/dispatch-fence";
import {watchRestoreActorName,watchDispatchActorName} from "../../../src/watch-lifecycle/dispatch-identity";
import { DurableObject } from "cloudflare:workers";
import { WatchRestoreAuthority } from "../../../src/watch-lifecycle/restore-authority";
export class DispatchActor extends DurableObject {
  private release: (() => void) | undefined;
  async fetch(req: Request) {
    const authority = new WatchRestoreAuthority(this.ctx.storage);
    const scope = fixtureScope(Number(new URL(req.url).searchParams.get("epoch") ?? 1), new URL(req.url).searchParams.get("receiver") ?? "watch", new URL(req.url).searchParams.get("fingerprint"));
    const env = this.env as any;
    if (new URL(req.url).pathname === "/revoke") {
      const fence = new WatchDispatchFence(this.ctx.storage, scope);
      const handler = createWatchRetirementHttp({
        db: env.DB, audience:"lab", now:() => Math.floor(Date.now()/1000),
        async resolveEnrolledKey() {
          const row = await env.DB.prepare("SELECT public_spki_hex FROM watch_lifecycle_issuer WHERE installation=? AND epoch=? AND key_fingerprint=? AND active=1").bind(scope.installation,scope.epoch,scope.key_fingerprint).first();
          return row?.public_spki_hex ? Uint8Array.from(row.public_spki_hex.match(/../g), (pair: string) => parseInt(pair,16)) : null;
        },
        async isRestoreCurrent(claims) { return claims.epoch===scope.epoch && claims.incarnation===scope.incarnation; },
        blockDispatch: (claims, hash) => fence.block(claims, hash),
        async hasDispatchBlock(claims, operation, hash) { return fence.hasBlock(claims, operation, hash); },
      }, (lookup, signal) => resolveWatchRetirementScope(env.DB, lookup, signal));
      return handler(req);
    }
    const payload: any = await req.json();
    switch (new URL(req.url).pathname) {
      case "/ready": return Response.json(this.release !== undefined);
      case "/resume": this.release?.(); return Response.json(true);
      case "/count": return Response.json(this.ctx.storage.sql.exec("SELECT count(*) AS count FROM starts").one().count);
      case "/send": {
        const sql = this.ctx.storage.sql;
        sql.exec("CREATE TABLE IF NOT EXISTS starts (id INTEGER PRIMARY KEY)");
        const db = new Proxy(env.DB, {
          get: (target, property) => {
            if (property !== "prepare") return Reflect.get(target, property, target);
            return (query: string) => {
              const stmt = target.prepare(query);
              if (!payload.pause || !query.includes("op.state='dispatching'")) return stmt;
              return {bind: (...values: unknown[]) => ({first: async () => {
                const row = await stmt.bind(...values).first();
                await new Promise<void>(resolve => {this.release = resolve;});
                return row;
              }})};
            };
          },
        });
        const now = Date.now();
        const send = createRestoredWatchSender({...payload.env, DB:db}, this.ctx, env.ACTOR,
          scope, () => now, async () => {
            sql.exec("INSERT INTO starts VALUES (NULL)");
            return new Response("{}", {status:200});
          });
        const service = createMomentTransport({
          db, now:()=>now, send, assertCurrent(){},
          limits:{capacity:16,installationCapacity:12,recipientBurst:5},
          async admit(event) { return {event_hash:await sha256Hex(canonical(event)),
            recipient_binding:"b".repeat(64),registration_binding:"c".repeat(64),
            eligible_since_ms:now-10000,expires_at_ms:now+30000,registration:payload.registration}; },
        });
        return Response.json((await service.dispatch(payload.event, new AbortController().signal)).state);
      }

      case "/init": return Response.json(authority.initializeDisabled(scope));
      case "/begin": return Response.json(await authority.begin(scope, payload.previous, payload.next));
      case "/confirm": return Response.json(authority.confirm(scope, payload));
      case "/advance": return Response.json(authority.advanceGeneration(scope, fixtureScope(scope.epoch+1)));
      default: {
        const sql = this.ctx.storage.sql;
        sql.exec("CREATE TABLE IF NOT EXISTS starts (id INTEGER PRIMARY KEY)");
        const result = authority.start(scope, payload, () => sql.exec("INSERT INTO starts VALUES (NULL)"));
        return Response.json(result !== null);
      }
    }
  }
}

function fixtureScope(epoch: number, receiver = "watch", fingerprint: string | null = null) {
  return {installation:"lab", receiver, incarnation:"pair-"+epoch, epoch, key_fingerprint:fingerprint ?? (epoch === 1 ? "a" : "b").repeat(64)};
}
export default {
  async fetch(req: Request, env: {ACTOR: DurableObjectNamespace}) {
    const url = new URL(req.url);
    const scope = fixtureScope(Number(url.searchParams.get("epoch") ?? 1), url.searchParams.get("receiver") ?? "watch", url.searchParams.get("fingerprint"));
    const name = url.searchParams.has("legacy") ? await watchDispatchActorName(scope) : await watchRestoreActorName(scope);
    return env.ACTOR.get(env.ACTOR.idFromName(name!)).fetch(req);
  },
};
