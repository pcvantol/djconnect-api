import {DurableObject} from 'cloudflare:workers';
// Only this test Worker binds a SQLite object. No command/owner bypass RPC exists.
export class QualificationRegistry extends DurableObject {}
export default {fetch(){return new Response('UNAVAILABLE',{status:503,headers:{'Cache-Control':'no-store'}});}};
