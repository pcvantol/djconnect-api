// LOCAL TEST EXPORTS ONLY. Two fixture classes exercise one inherited SQLite authority, no product binding.
export {ReceiptKeyStore} from './receipt-key-store';
export {AssertionKeyState} from './assertion-key-state';
export default {fetch(){return new Response('qualification only',{status:503,headers:{'Cache-Control':'no-store'}});}};
