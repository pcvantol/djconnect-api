/** Portable private-library entry. Public requests remain unavailable.
 * Positive private composition must supply the original real clock, D1,
 * existing identity/policy and transport; this entry supplies none. */
export {createReceivingService} from '../service';
export default {fetch(){return new Response(null,{status:503});}};
