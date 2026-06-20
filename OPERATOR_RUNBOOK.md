# DJConnect API Operator Runbook

Operational procedures for `api.djconnect.dev`.

All commands and examples in this document are public-repo safe. Replace
example values locally only. Do not paste real APNs tokens, `.p8` contents,
Cloudflare tokens, relay secrets, Home Assistant tokens or production
identifiers into issues, pull requests, logs or screenshots.

## APNs Token Encryption Key Rotation

`APNS_TOKEN_ENCRYPTION_KEY` protects APNs device tokens stored in D1. The key is
a base64-encoded 32-byte AES-GCM key stored only as a Cloudflare Worker secret.
Rows store encrypted token material in:

- `apns_token_ciphertext`
- `apns_token_nonce`
- `apns_token_key_version`

`apns_token_key_version` is a non-secret SHA-256-derived prefix for identifying
which key encrypted a row. It is safe to store in D1 and use in counts.

### Rotation Rules

- Never print old or new encryption keys.
- Never commit old or new encryption keys.
- Never put `APNS_TOKEN_ENCRYPTION_KEY` in GitHub Actions, `.env`, `.dev.vars`
  or docs.
- Keep the old key until every row has been re-encrypted and verified.
- If the old key is lost, existing encrypted APNs tokens cannot be decrypted.
  Affected Apple clients must register again.
- Do not rotate during a high-traffic period unless the runtime supports both
  current and previous keys.

### Preferred Zero-Downtime Rotation

Use this flow for planned production rotations.

1. Generate a new key locally:

   ```sh
   openssl rand -base64 32
   ```

2. Keep both values only in the operator shell/session:

   ```sh
   export APNS_TOKEN_ENCRYPTION_KEY_OLD_VALUE='replace-locally'
   export APNS_TOKEN_ENCRYPTION_KEY_NEW_VALUE='replace-locally'
   ```

3. Deploy a temporary dual-key runtime/backfill change before replacing the
   Worker secret:

   - Current key: `APNS_TOKEN_ENCRYPTION_KEY`
   - Previous key: `APNS_TOKEN_ENCRYPTION_KEY_PREVIOUS`
   - Decrypt old rows with the key whose version matches
     `apns_token_key_version`.
   - Encrypt all new registrations with the current key.
   - Re-encrypt old rows to the new key through a one-off operator backfill
     script or endpoint that never returns decrypted APNs tokens.

4. Install the previous key as a temporary Cloudflare Worker secret:

   ```sh
   env -u CLOUDFLARE_API_TOKEN npx wrangler secret put APNS_TOKEN_ENCRYPTION_KEY_PREVIOUS
   ```

5. Install the new current key as the Cloudflare Worker secret:

   ```sh
   env -u CLOUDFLARE_API_TOKEN npx wrangler secret put APNS_TOKEN_ENCRYPTION_KEY
   ```

6. Run the backfill in small batches:

   - Select rows where `apns_token_ciphertext IS NOT NULL`.
   - Skip rows already on the new `apns_token_key_version`.
   - Decrypt token material in memory only.
   - Re-encrypt with the new key and a new nonce.
   - Update only `apns_token_ciphertext`, `apns_token_nonce`,
     `apns_token_key_version` and `updated_at`.
   - Do not log plaintext tokens, ciphertext, nonces or request bodies.

7. Verify with count-only D1 queries:

   ```sql
   SELECT apns_token_key_version, COUNT(*) AS count
   FROM registrations
   WHERE apns_token_ciphertext IS NOT NULL
   GROUP BY apns_token_key_version;
   ```

   ```sql
   SELECT COUNT(*) AS legacy_plain_rows
   FROM registrations
   WHERE apns_token IS NOT NULL;
   ```

   ```sql
   SELECT COUNT(*) AS missing_encrypted_rows
   FROM registrations
   WHERE disabled = 0
     AND invalid = 0
     AND apns_token_ciphertext IS NULL;
   ```

8. Run safe smoke checks:

   ```sh
   curl -fsS https://api.djconnect.dev/health
   npm run postman:test
   ```

   If GitHub Actions `DJCONNECT_RELAY_SECRET` is configured, run the CI/CD
   workflow and confirm `Smoke E2E: success`.

9. After every encrypted row is on the new key version and smoke checks pass,
   remove the temporary previous-key secret and deploy code that no longer
   references it.

10. Unset local shell values:

    ```sh
    unset APNS_TOKEN_ENCRYPTION_KEY_OLD_VALUE
    unset APNS_TOKEN_ENCRYPTION_KEY_NEW_VALUE
    ```

### Emergency Rotation

Use this only when the current key is suspected compromised.

1. Preserve the old key if it is still known. Without it, existing encrypted
   APNs tokens are unrecoverable.
2. Generate and install a new `APNS_TOKEN_ENCRYPTION_KEY`.
3. Revoke or rotate any operator credentials that may have exposed the old key.
4. Backfill any rows that can still be decrypted with the old key.
5. For rows that cannot be decrypted, mark the registration disabled and allow
   Apple clients to register again.

### Current Implementation Note

The current production Worker uses one `APNS_TOKEN_ENCRYPTION_KEY` for decrypt
and encrypt. It does not yet include a committed dual-key backfill endpoint or
script. Therefore:

- Planned key rotation must first ship a temporary dual-key/backfill change, or
  be performed during a maintenance window with careful two-pass backfill.
- Do not simply overwrite `APNS_TOKEN_ENCRYPTION_KEY` unless all existing
  encrypted rows have already been re-encrypted or can safely be re-registered.
