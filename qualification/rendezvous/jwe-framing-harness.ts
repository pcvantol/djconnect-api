// ISOLATED LOCAL QA ENTRY ONLY. No service endpoint or product bindings.
export default {async fetch(){return new Response(null,{status:503,headers:{'Cache-Control':'no-store'}});}};
