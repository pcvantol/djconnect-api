declare module 'djc-qualified-assertion' {
 // Invalid proof returns null; fixed assertion WebCrypto exceptions reject for coordinator classification.
 export function qualifyAssertionCore(proof:Uint8Array,clientData:Uint8Array,point:Uint8Array,previousCounter:number):Promise<{counter:number;scope:string}|null>;
}
