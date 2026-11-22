# SmartGridShield Architecture

```text
User -> Demo Verification Authority -> Registration API -> Credential Issuer
                                              |                  |
                                              v                  v
                                       Encrypted Identity Vault  Ed25519 credential
                                              |                  |
Accountability workflow <--- audit log <-----+----> Challenge / Proof verifier
                                                           |
                                     +---------------------+---------------------+
                                     |                     |                     |
                                  P2P Trading          EV Charging           Microgrid
```

## Normal authentication

1. A Smart Grid identity requests a service/action challenge.
2. The backend generates an unpredictable nonce, binds it to the service/action, and stores a 120-second challenge.
3. The demo wallet signs the challenge with the holder key.
4. The backend verifies the issuer credential, holder-key proof, revocation state, service permission, expiry, and one-time challenge state.
5. The service receives a deterministic service-scoped pseudonym rather than real-world identity data.

## Controlled identity recovery

1. A requester creates an investigation with an incident ID, reason, evidence and target Smart Grid ID.
2. A different approver approves or rejects it.
3. Only an approved case can decrypt the protected vault mapping.
4. Creation, approval/rejection, and recovery are audited.

## Deliberate prototype boundary

This project uses an encrypted server-held demo wallet adapter for presentation. A production design must keep holder keys in a hardware-backed or independently controlled user wallet.
