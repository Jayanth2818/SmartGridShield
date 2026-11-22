# SmartGridShield

Separate local research prototype; it does not modify the earlier GridPass demo.

## Run

```powershell
cd SmartGridShield\backend
pip install -r requirements.txt
uvicorn main:app --port 8001
```

In another terminal:

```powershell
cd SmartGridShield\frontend
npm install
npm run dev
```

Use `DEMO-ALICE-1001`, `DEMO-BOB-2002`, or `DEMO-CHARLIE-3003` during registration. These are fictional test identities only.

## Security boundaries

Implemented: Ed25519 issuer credential signatures, Ed25519 proof verification, Argon2id password hashing, Fernet encryption of identity vault records, server-side challenge expiry/consumption and service authorization.

The `demo-wallet-proof` endpoint exists only so a browser-only research presentation can execute the protocol. It is not a production wallet: production systems must hold the private key outside the server. Government verification and energy systems are simulations. No zero-knowledge, anonymous-credential, unlinkability, or real-government claims are made.

## Current functional coverage

- Smart Grid identity registration and mock verification.
- Smart Card login and prepared presentation identity.
- Issuer-signed challenge-response authentication before entry to each service.
- P2P buyer/seller, EV driver/operator, and Microgrid participant/operator simulated operations, persisted to SQLite.
- Credential revocation immediately blocks new challenges.
- Investigation lifecycle: requester creates a case, a different approver decides, and identity recovery is allowed only after approval. All lifecycle actions are audited.
- Short-lived service authorization: an operation is denied until that exact service has completed a successful authentication, then expires after two minutes.
- Protected administrator summary and service-permission-management API using a local demonstration administrator key.

## Test

```powershell
cd SmartGridShield\backend
python -m pytest -q
```

The test suite currently covers signed-proof authentication, replay rejection, tampered credential rejection, revocation, investigation self-approval rejection, approval, and controlled recovery.

Read [Architecture](docs/ARCHITECTURE.md) and the [Threat Model](docs/THREAT_MODEL.md) before presenting the security claims.
