// Local node/workerd conformance bridge only; excluded from packaged source Worker.
import type {CoordinatorSourceState as State} from '../state';
export {CoordinatorSourceState} from '../state';
export {SourceStateOutbound} from '../outbound';
interface Env {SOURCE_STATE:DurableObjectNamespace<State>}
export default {async fetch(request:Request,env:Env,ctx:ExecutionContext):Promise<Response> {
  const url=new URL(request.url);
  if(url.hostname!=='127.0.0.1' || url.pathname!=='/source-transaction' || url.search || request.method!=='POST')return new Response(null,{status:503});
  const exports=ctx.exports as unknown as {SourceStateOutbound(options:{props:{stateId:string}}):Fetcher};
  const own=env.SOURCE_STATE.idFromName('local-node-source-conformance');
  const outbound=exports.SourceStateOutbound({props:{stateId:own.toString()}});
  return outbound.fetch(new Request('http://coordinator.state/source-transaction',request));
}};
