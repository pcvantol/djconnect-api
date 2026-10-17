// Test-only Worker export. No enrollment/admin/data endpoint exists.
export { ReceiptKeyStore } from './receipt-key-store';
export default { fetch(){ return new Response('local qualification only',{status:503,headers:{'Cache-Control':'no-store'}}); } };
