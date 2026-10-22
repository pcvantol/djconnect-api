import { base64Encode, base64Decode } from "../crypto";
const encoder = new TextEncoder();
async function key(value: string): Promise<CryptoKey> {
 const bytes = base64Decode(value); if (bytes.length !== 32) throw new Error("surface_key_configuration");
 return crypto.subtle.importKey("raw", bytes, "AES-GCM", false, ["encrypt", "decrypt"]);
}
export async function seal(token: string, secret: string, aad: string): Promise<{ ciphertext: string; nonce: string }> {
 const nonce = crypto.getRandomValues(new Uint8Array(12));
 const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: encoder.encode(aad) }, await key(secret), encoder.encode(token));
 return { ciphertext: base64Encode(ciphertext), nonce: base64Encode(nonce) };
}
export async function unseal(ciphertext: string, nonce: string, secret: string, aad: string): Promise<string> {
 return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64Decode(nonce), additionalData: encoder.encode(aad) }, await key(secret), base64Decode(ciphertext)));
}
