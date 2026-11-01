declare module 'djc-shipped-receiving' {
 export const createReceivingService:typeof import('../service').createReceivingService;
 const closed:{fetch(request?:Request):Response|Promise<Response>};
 export default closed;
}
