import { sha256Hex } from 'djc-existing-crypto';

type AppAttestEnvironment = 'development' | 'production';

/** Used by enrollment, assertion and submit to address the same attested key. */
export function rendezvousKeyAddress(
  keyId: string,
  environment: AppAttestEnvironment,
  appPolicy: string,
): Promise<string> {
  return sha256Hex(JSON.stringify([environment, appPolicy, keyId]));
}
