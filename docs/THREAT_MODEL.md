# Threat Model and Security Claims

## Mitigated in the prototype

| Threat | Control |
|---|---|
| Credential modification/forgery | Ed25519 issuer signature verification |
| Replay | Unique nonce, short expiry, consumed flag |
| Stolen credential without key | Holder-key signature proof |
| Revoked card | Server-side credential revocation check |
| Unauthorised service | Service permission check |
| Sensitive operation before login | Short-lived authenticated service session required |
| Direct identity lookup | Separate Fernet-encrypted vault; recovery endpoint needs approved case |
| Requester self-approval | Backend rejects it |

## Assumptions

- The API server, database access control, issuer key and vault key are trusted for this local prototype.
- Test identities and energy assets are fictional.
- The local administrator key is strictly a classroom-demo mechanism.

## Not claimed

The prototype does not provide zero-knowledge proof, anonymous credentials, unlinkability between services, production key custody, HSM/KMS protection, real government verification, or safety-certified grid control.
