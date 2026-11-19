export {PrincipalRegistryData} from './registry';
/** Registrar trust/Core-install bootstrap is not supplied by the Worker/DO hosting choice. */
export function createProductionRegistry(..._args:unknown[]):never {
  throw new Error('registrar authority/Core-install trust/restore/read policy unavailable');
}
export default {fetch():Response {
  return new Response('{"state":"UNAVAILABLE"}',{status:503,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
}};
