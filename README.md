# SmartGridShield

> Privacy-preserving and accountable authentication for a fictional Smart Grid 2.0 ecosystem.

SmartGridShield is an end-semester research prototype that demonstrates a practical identity lifecycle:

```text
Mock real-world verification → Smart Grid Card issuance → challenge-response access
→ scoped service operations → controlled, audited identity recovery
```

It is a local-only demonstration. It uses only fictional identities, fictional energy services, and simulated grid operations. It does **not** connect to Aadhaar, government identity systems, energy infrastructure, charging stations, or payment systems.

## What it demonstrates

- Simulated Government Verification Authority with safe test identities.
- Separate real-world identity vault and Smart Grid identity.
- Opaque Smart Grid Card (`SGS-...`) issuance.
- Argon2id password hashing for registration credentials.
- Ed25519 issuer-signed credentials.
- Ed25519 holder-key challenge proof in the authentication protocol.
- Cryptographically random, expiring, single-use authentication challenges.
- Service- and action-bound authentication.
- Server-side credential revocation and service permission checks.
- Fernet authenticated encryption of vault identity mappings.
- Service-scoped pseudonyms rather than legal identities in normal authentication responses.
- P2P buyer/seller, EV driver/operator, and Microgrid participant/operator workflows.
- Persisted service-operation history in SQLite.
- Controlled investigation → independent approval → identity recovery workflow.
- Audit records and CSV export.
- A presentation-ready prepared demo identity and seeded sample history.

## Technology

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI, Pydantic |
| Persistence | SQLite, SQLAlchemy |
| Credential signatures | Ed25519 via `cryptography` |
| Vault encryption | Fernet via `cryptography` |
| Password hashing | Argon2id via `argon2-cffi` |
| Tests | Pytest + FastAPI TestClient |

## Project layout

```text
SmartGridShield/
├── backend/
│   ├── main.py                 # API, data models, crypto and seed data
│   ├── test_security.py         # Security/integration tests
│   └── requirements.txt
├── frontend/
│   ├── src/main.tsx             # React application
│   ├── src/style.css
│   └── package.json
├── docs/
│   ├── ARCHITECTURE.md
│   └── THREAT_MODEL.md
└── README.md
```

## Quick start (Windows)

Requirements: Python 3.11+ and Node.js 20+.

### 1. Run the backend

```powershell
cd SmartGridShield\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8001
```

Backend API documentation: `http://127.0.0.1:8001/docs`

### 2. Run the frontend

Open a second terminal:

```powershell
cd SmartGridShield\frontend
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173`.

## Ready-made demo data

On first startup, the backend creates only fictional seed data:

| Item | Value |
|---|---|
| Prepared Smart Grid Card | `SGS-DEMO-ALICE` |
| Demo user | Alice Demonstration |
| Permissions | P2P Trading, EV Charging, Microgrid |
| Sample P2P record | Energy purchase from Sunrise Solar Co-op |
| Sample EV record | Completed Central Hub charging session |
| Sample Microgrid record | Accepted demand response request |
| Sample investigation | Approved fictional research case |

Use **Enter prepared demo** from the landing or login page for the fastest presentation flow.

Safe simulated registration identities are:

```text
DEMO-ALICE-1001
DEMO-BOB-2002
DEMO-CHARLIE-3003
```

They are fictional test values only. Never use a real government ID.

## Suggested presentation walkthrough

1. Open the landing page and click **Enter prepared demo**.
2. Show the dashboard and digital Smart Grid Card.
3. Explain that the card represents a Smart Grid identity, not the holder's government identity.
4. Open **Services** and choose P2P Trading, EV Charging, or Microgrid.
5. Show that service entry triggers fresh challenge-response authentication.
6. In each service, demonstrate both perspectives:
   - P2P: buy energy and publish a seller listing.
   - EV: start a driver session and use operator controls.
   - Microgrid: request participation and execute a simulated operator action.
7. Open **Attack Lab** and run replay, forged-credential, stolen-credential-without-key, and unauthorised-recovery scenarios.
8. Open **Credentials** and revoke the demo credential. Show that subsequent challenges are blocked.
9. Open **Accountability**, create a case, approve it as the independent reviewer, then perform recovery.
10. Open **Audit** to show logged events and export CSV.
11. Open **Admin** to show summary metrics and service-permission management.

For a clean repeatable run after revocation, delete `backend/smartgridshield.db` while the server is stopped; restarting creates a fresh fictional demo dataset.

## Authentication protocol

```text
1. User requests service + action
2. Backend generates 32-byte URL-safe random nonce
3. Challenge is stored with Smart Grid ID, service, action, expiry, and consumed state
4. Demo wallet signs challenge data with holder Ed25519 private key
5. Backend verifies:
   - issuer credential signature
   - holder-key proof
   - service permission
   - revocation state
   - challenge service/action binding
   - expiry
   - one-time consumption state
6. Backend issues a short-lived authenticated service-operation window
7. Service receives a service-scoped pseudonym and decision
```

The challenge string signed by the holder is bound to:

```text
challenge_id | nonce | service | action
```

## Privacy model

### Normal service access sees

- A service-specific pseudonym.
- Verified/accepted authentication result.
- Required authorization result.
- Requested service and action.

### Normal service access does not receive

- Government ID.
- Legal name.
- Contact information.
- Identity-vault mapping.

The identity vault is stored separately and its JSON record is Fernet-encrypted. Recovery requires an approved investigation case; a requester cannot approve their own investigation.

## Security testing

Run all backend tests:

```powershell
cd SmartGridShield\backend
python -m pytest -q
```

The current suite verifies:

- Valid signed proof authentication.
- Replay rejection after a consumed challenge.
- Tampered/forged credential rejection.
- Credential revocation blocks new service challenges.
- Service operation is rejected before fresh service authentication.
- Service operation succeeds only after matching authentication.
- Expired challenge rejection.
- Service permission denial.
- Investigation requester cannot self-approve.
- Approved investigation enables controlled recovery.
- Administrator endpoints reject missing or incorrect authorization.

## API overview

| API | Purpose |
|---|---|
| `POST /api/register` | Mock verification and Smart Grid credential issuance |
| `POST /api/card-login` | Local demo Smart Card login |
| `POST /api/prepared-demo` | Loads seeded classroom demo identity |
| `POST /api/challenges/{sg_id}/{service}/{action}` | Creates an authentication challenge |
| `POST /api/authenticate` | Verifies issuer credential, key proof, and challenge |
| `POST /api/service/{service}/action` | Persists a protected simulated operation |
| `GET /api/service/{service}/history/{sg_id}` | Reads operation history |
| `POST /api/credentials/{sg_id}/revoke` | Revokes a credential |
| `POST /api/investigations` | Creates an accountability case |
| `POST /api/investigations/{id}/decision` | Approves or rejects a case |
| `POST /api/investigations/{id}/recover` | Recovers vault identity after approval |
| `GET /api/audit` | Reads audit events |
| `GET /api/audit/export` | Exports audit records as CSV |
| `GET /api/admin/summary` | Demo administrator system summary |

Full interactive API documentation is available at `/docs` while the backend runs.

## Security limitations and honest claims

This is a research prototype, not a production identity platform.

### Implemented

- Reputable cryptographic primitives instead of custom cryptography.
- Ed25519 credential signing and verification.
- Holder-key proof demonstration.
- Argon2id password hashing.
- Fernet-encrypted vault values.
- Nonce freshness and replay prevention.
- Service/action binding.
- Revocation checks.
- Permission checks.
- Short-lived post-authentication service-operation authorization.
- Audited, independently approved recovery flow.

### Simulated

- Government verification authority.
- Card reader and user wallet.
- P2P market, charging stations, microgrid operations, energy settlement, and receipts.
- Accountability organization and administrator workflow.

### Not implemented or claimed

- Zero-knowledge proofs.
- Anonymous credentials.
- Cryptographic unlinkability between services.
- Real government identity assurance.
- Real Aadhaar or government-ID integration.
- Hardware-backed wallet keys.
- HSM/KMS key custody or rotation.
- Production-grade session/login security.
- Safety-certified smart-grid control.
- Real payment or energy delivery.

The browser demo uses a **server-held encrypted demo wallet adapter** to make the challenge-proof interaction demonstrable in a single local application. A production system must keep the holder private key outside the server, for example in a hardware-backed wallet.

## Demo administrator note

The project contains a deliberately local, classroom-only administrator key to protect demo administrator endpoints. It is not a production credential and must be replaced by authenticated role/session enforcement in any real deployment.

## Further reading

- [System architecture](docs/ARCHITECTURE.md)
- [Threat model and security claims](docs/THREAT_MODEL.md)

## License

This project is intended for academic demonstration and research use. Add your institution's preferred license before redistributing it.
