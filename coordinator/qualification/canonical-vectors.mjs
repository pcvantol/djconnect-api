// Independent JS encoding parity only, not a native/protocol authority validator.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
const packet = JSON.parse(readFileSync(new URL('./passive-vectors.json', import.meta.url), 'utf8'));
for (const vector of packet.vectors) {
  const bytes = Buffer.from(JSON.stringify(JSON.parse(vector.canonical_utf8)), 'utf8');
  if (bytes.toString('hex') !== vector.hex || createHash('sha256').update(bytes).digest('hex') !== vector.sha256) {
    throw new Error(`Synthetic canonical byte mismatch: ${vector.name}`);
  }
}
console.log(JSON.stringify({ classification: 'SYNTHETIC_ENCODING_PARITY_ONLY', vectors: packet.vectors.length }));
