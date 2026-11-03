import { DurableObject } from "cloudflare:workers";
import { WatchDispatchFence } from "../../src/watch-lifecycle/dispatch-fence";

import { watchDispatchActorName } from "../../src/watch-lifecycle/dispatch-identity";

function fixtureScope(request: Request) {
  return { installation: "lab", receiver: new URL(request.url).searchParams.get("installation") ?? "",
    incarnation: "pair", epoch: 1, key_fingerprint: "a".repeat(64) };
}

export class DispatchActor extends DurableObject {
  async fetch(request: Request) {
    const url = new URL(request.url);
    const claims = { ...fixtureScope(request), audience: "lab", action: "retire" as const,
      operation: "revoke", expiry: 1 };
    const fence = new WatchDispatchFence(this.ctx.storage, claims);
    const hash = "b".repeat(64);
    const sql = this.ctx.storage.sql;
    sql.exec("CREATE TABLE IF NOT EXISTS fixture_start (id INTEGER PRIMARY KEY)");
    if (url.pathname === "/revoke") {
      if (!(await fence.block(claims, hash))) return new Response(null, { status: 500 });
      if (!(await fence.block(claims, hash)) || await fence.block(claims, "c".repeat(64)))
        return new Response(null, { status: 500 });
      return Response.json({ revoked: true });
    }
    if (url.pathname === "/start") {
      const admitted = fence.start(claims, "d".repeat(64), url.searchParams.get("lease") ?? "lease-a", Number(url.searchParams.get("now") ?? 1000), Number(url.searchParams.get("expires") ?? 1500), () => {
        sql.exec("INSERT INTO fixture_start VALUES (NULL)");
      }) !== null;
      return Response.json({ admitted });
    }
    return Response.json({ revoked: Number(fence.hasBlock(claims, "revoke", hash)),
      starts: sql.exec("SELECT count(*) AS count FROM fixture_start").one().count });
  }
}
export default {
  async fetch(request: Request, env: { ACTOR: DurableObjectNamespace }) {
    const name = await watchDispatchActorName(fixtureScope(request));
    if (name === null) return new Response(null, { status: 400 });
    return env.ACTOR.get(env.ACTOR.idFromName(name)).fetch(request);
  },
};
