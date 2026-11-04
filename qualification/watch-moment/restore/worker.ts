import {createRestoredWatchSender} from "../../../src/watch-lifecycle/restore-dispatch";
import {WatchDispatchFence} from "../../../src/watch-lifecycle/dispatch-fence";
import {watchRestoreActorName,watchDispatchActorName} from "../../../src/watch-lifecycle/dispatch-identity";
import { DurableObject } from "cloudflare:workers";
import { WatchRestoreAuthority } from "../../../src/watch-lifecycle/restore-authority";
export class DispatchActor extends DurableObject {
  private release: (() => void) | undefined;
  async fetch(req: Request) {
    const authority = new WatchRestoreAuthority(this.ctx.storage);
    const scope = fixtureScope(Number(new URL(req.url).searchParams.get("epoch") ?? 1), new URL(req.url).searchParams.get("receiver") ?? "watch");
    const payload: any = await req.json();
    switch (new URL(req.url).pathname) {
      case "/revoke": {
        const claims = {...scope, action:"retire" as const, audience:"lab", operation:"revoke", expiry:1};
        return Response.json(await new WatchDispatchFence(this.ctx.storage, scope).block(claims, "d".repeat(64)));
      }
      case "/ready": return Response.json(this.release !== undefined);
      case "/resume": this.release?.(); return Response.json(true);
      case "/count": return Response.json(this.ctx.storage.sql.exec("SELECT count(*) AS count FROM starts").one().count);
      case "/send": {
        const sql = this.ctx.storage.sql;
        sql.exec("CREATE TABLE IF NOT EXISTS starts (id INTEGER PRIMARY KEY)");
        const db = {prepare: (query: string) => ({bind: (...values: unknown[]) => ({first: async () => {
          const row = await (this.env as any).DB.prepare(query).bind(...values).first();
          if (payload.pause) await new Promise<void>(resolve => {this.release = resolve;});
          return row;
        }})})};
        const now = Date.now();
        const send = createRestoredWatchSender({...payload.env, DB:db}, this.ctx, (this.env as any).ACTOR,
          scope, {operation:"e".repeat(64),lease:"lease"}, () => now, async () => {
            sql.exec("INSERT INTO starts VALUES (NULL)");
            return new Response("{}", {status:200});
          });
        try {
        const result = await send(payload.registration, {aps:{alert:"lab"}}, {
          headers:{},expiresAt:now+30000,signal:new AbortController().signal,beforeFetch:async()=>now,
        });
        return Response.json(result.status);
        } catch (error) {
          if (!(error instanceof Error) || error.message !== "watch_dispatch_unavailable") throw error;
          return Response.json(0);
        }
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

function fixtureScope(epoch: number, receiver = "watch") {
  return {installation:"lab", receiver, incarnation:"pair-"+epoch, epoch, key_fingerprint:(epoch === 1 ? "a" : "b").repeat(64)};
}
export default {
  async fetch(req: Request, env: {ACTOR: DurableObjectNamespace}) {
    const url = new URL(req.url);
    const scope = fixtureScope(Number(url.searchParams.get("epoch") ?? 1), url.searchParams.get("receiver") ?? "watch");
    const name = url.searchParams.has("legacy") ? await watchDispatchActorName(scope) : await watchRestoreActorName(scope);
    return env.ACTOR.get(env.ACTOR.idFromName(name!)).fetch(req);
  },
};
