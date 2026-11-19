import {DurableObject} from 'cloudflare:workers';
/** Dedicated target class, closed until independently qualified management composition exists.
 * Construction does not initialize SQL, import a key, create an owner or issue a challenge. */
export class InstallationRegistryObject extends DurableObject {
  fetch():Response {return unavailable();}
}
export function createProductionInstallationRegistry(..._args:unknown[]):never {
  throw new Error('independent operator/install/custody/clock/restore/withdrawal admission unavailable');
}
function unavailable():Response {return new Response('{"state":"UNAVAILABLE"}',{status:503,
  headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});}
export default {fetch:unavailable};
