declare module 'djc-qualified-assertion' {
 export function qualifyAssertionCore(proof:Uint8Array,clientData:Uint8Array,point:Uint8Array,previousCounter:number):Promise<{counter:number;scope:string}|null>;
}
