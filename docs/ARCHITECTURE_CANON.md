Cybersuite – Architecture Canon
Doc-Version: AC-1.7.0
Stand: 2026-03
Status: Blueprint → Neuaufbau Stage 1–6 + BC live subset + PQC/ML + Security-Audit + Logging + KeyImport + NonceSafety + Thread-Safety-Hardening + Handle-Only-Egress + SensitiveBufferLease + KeyExportPolicy
Sprache: de-CH

Dieser Canon ist die Single Source of Truth für die Architektur. Der CYBERSUITE_STATE ist der kompakte, reinjectable Index (Version/Status/Decisions). Bei Konflikten gilt: Canon-Text > State, ausser State enthält eine explizite Decision-ID.

[CON-000] Vision und Ziel
Cybersuite ist eine crypto-agile Suite zur policy-gesteuerten, auditierbaren Bereitstellung von Kryptodiensten (klassisch, PQC, Hybrid) über einen Multi-Provider-Ansatz mit Provider Isolation (hybrid: default out-of-process), downgrade-resistenter Negotiation und FIPS-/Compliance-Bewusstsein.

Primäre Outcomes
Policy steuert: SecurityMode (klassisch/PQC/Hybrid), erlaubte Algorithmen/Parameter, Provider-Pinning
Deterministische, fail-closed Algorithm Selection mit Anti-Downgrade-Invarianten
Provider Lifecycle + Trust Evaluation + (optional) Attestation
Kein Secret-Leakage in Logs/Audit; Secrets als Handles (insb. bei OOP/HSM)
Schichtentrennung (Clean Architecture), thread-safe by design
Non-Goals
Keine produktionsreife Kryptoprimitive im Core
Kein vollständiges KMS
Keine vollständige formale Verifikation im ersten Durchlauf
[ARC-020] Layered Clean Architecture
Cybersuite.Abstractions
Cybersuite.Policy
Cybersuite.Selection
Cybersuite.ProviderModel
Cybersuite.OopProtocol
Cybersuite.ProviderHost
Cybersuite.Compliance
Cybersuite.Runtime
Dependency Rules
Nur nach innen
Keine Zyklen
Selection kennt keinen Transport/ProviderHost
ProviderHost kennt keine Policy-Interna
Runtime orchestriert, implementiert aber keine Kryptographie
Konkrete Provider liegen ausserhalb von src/
[ARC-030] Kernkonzepte
PolicySnapshot und CapabilitySnapshot sind immutable
Snapshots sind thread-safe
AlgorithmDescriptor trägt:
AlgorithmId
ProviderId
Category
SecurityMode
Strength / optional HybridStrength
IsFipsApproved
optional ParameterSetId
OperationalMaturity
EncodingProfile
[ARC-031] Parameter Sets and Encoding Profiles
Für PQC/ML reichen AlgorithmId + Strength + SecurityMode nicht aus.
Daher werden zusätzlich geführt:

AlgorithmParameterSetId
AlgorithmOperationalMaturity
AlgorithmEncodingProfile
Beispiele:

AlgorithmId = ML-KEM-768, ParameterSetId = ML-KEM-768
AlgorithmId = ML-DSA-65, ParameterSetId = ML-DSA-65
[PM-010] CapabilityArtifactProfile
CapabilityArtifactProfile beschreibt pro Algorithmus die Artefaktgrössen und Default-Encoding-Hinweise, z. B.:

PublicKeyBytes
CiphertextBytes
SignatureBytes
SharedSecretBytes
NonceBytes
TagBytes
PublicKeyEncodingProfile
PrivateKeyEncodingProfile
Diese Information ist nicht geheim und wird in den deterministischen CapabilitySnapshot aufgenommen und damit gehasht.

[CMP-000] Dual Compliance Gate
Für PQC/ML ist ein einziges Flag IsFipsApproved nicht ausreichend.
Es gelten zwei Gates:

Algorithm Approval

Algorithmus/Parameter‑Satz selbst zulässig?
abgebildet u. a. über IsFipsApproved, OperationalMaturity
Boundary / Module Approval

läuft der Provider in einer zulässigen Boundary / einem zulässigen Modulpfad?
abgebildet über ProviderMetadata.ComplianceProfile + ProviderRecord.FipsBoundaryDeclared
Runtime-Verhalten
Der Compliance-Layer kann nach der Selection die Auswahl validieren
Bei Verstoß: fail-closed
Experimental kann profilabhängig erlaubt/verboten sein
FIPS verlangt algorithm approval + boundary approval
[OOP-052] Key Import / Export Contracts
Für operative ML‑Einbindung reichen KeyGen/Sign/Verify/Encaps/Decaps nicht aus.
Daher existieren:

IKeyImportService
IKeyExportService
IKeySerializationSession
Diese Contracts sind additive Erweiterungen und noch nicht zentral verdrahtet.

[PH-023] Concrete Bouncy Castle Binding (current + ML delta)
Die konkrete BC-Live-Bindung unterstützt jetzt:

Classical stable subset
ECDH-P384-KEM
ECDSA-P384
AES-256-GCM
HKDF-SHA384
SHA-384
PQC experimental subset
ML-KEM-512
ML-KEM-768
ML-KEM-1024
ML-DSA-44
ML-DSA-65
ML-DSA-87
Architekturregel
PQC-Fähigkeiten werden als OperationalMaturity = Experimental markiert
OSS-BC bleibt nicht FIPS
PQC-Live-Binding darf fail-closed mit NotSupportedException enden, wenn die installierte BC-Version die erwarteten PQC-Typen nicht tatsächlich exponiert
[PH-024] ML-KEM Integration
Die ML-KEM-Implementierung folgt dem bestehenden IKemService-Modell:

GenerateKeyPair
Encapsulate
Decapsulate
Operational wird die BC-PQC-API via Reflection gebunden, um compile-time Stabilität gegen BC-Namespace-/Typänderungen zu wahren.

[PH-025] ML-DSA Integration
Die ML-DSA-Implementierung folgt dem bestehenden ISignatureService-Modell:

GenerateKeyPair
Sign
Verify
Auch hier erfolgt die BC-Bindung reflection-based und fail-closed.

[SEC-THR-000] Thread-Safety Invarianten
Keine mutable statics
Snapshots immutable
ProviderHost Registry lock-free read / atomic write (ImmutableInterlocked)
ProviderSession counter via Interlocked, OperationSyncRoot für Op-Serialisierung
Runtime lifecycle via SemaphoreSlim
BC connection uses private lock + isolated key store
ML reflection helpers sind stateless
BouncyCastleKeyMaterialStore: `lock(_gate)` + `_disposed` Guard auf allen 12 öffentlichen Methoden
SessionHandleTracker: `lock(_gate)` mit DrainAll-Semantik
SensitiveBufferLease: `Interlocked.Exchange` für thread-safe Dispose
ProviderRpcSession + Proxies: `Interlocked.CompareExchange` für Dispose-Guard
LiveProviderSessionState: `Volatile.Read`/`Write` für Stop-Flag, `Interlocked.Increment` für Counter
ProviderHost: `SemaphoreSlim` für Lifecycle, `ConcurrentDictionary` für Sessions
BouncyCastleOutOfProcessConnection: `SemaphoreSlim(1,1)` für RPC-Serialisierung
Use-after-Dispose: `ObjectDisposedException.ThrowIf` in KeyMaterialStore

[SEC-THR-001] Dead-Code-Bereinigung (Phase 7)
Entfernte Methoden aus BouncyCastleKeyMaterialStore:
  - GetSecretKeyCopy
  - GetSharedSecretCopy
  - BorrowSecretKey
  - BorrowSharedSecret
Diese Methoden waren nach der F5-SensitiveBufferLease-Migration verwaist und stellten potentielle Bypass-Pfade für das Handle-Only-Modell dar.
[SEC-SC-000] Side-Channel Leitlinien
CryptographicOperations.FixedTimeEquals für Hash/Bindings
Keine secret-abhängigen early exits in sensitiven Vergleichen
Keine secrets in exception messages/logs
Handles sind sensitive identifiers: no logging
temporäre Secret-Bytearrays werden nach Gebrauch zeroized

[SEC-SC-001] SensitiveBufferLease (F5 – Heap-Kopien-Reduktion)
SensitiveBufferLease kapselt gepoolte Puffer via `ArrayPool<byte>.Shared`:
  - Rent/CopyFrom/Span/DangerousGetArray
  - Dispose: `CryptographicOperations.ZeroMemory` + Pool-Rückgabe
  - Thread-safe Dispose via `Interlocked.Exchange`
  - Idempotent: doppeltes Dispose ist sicher
Verwendet in:
  - BouncyCastleProviderConnection: AeadEncrypt/Decrypt, KdfDeriveKey, ComputeSha384
  - BouncyCastleKeyMaterialStore: LeaseSecretKey, LeaseSharedSecret
AEAD-Messages (AeadEncryptRequest/Response, AeadDecryptRequest/Response) sind IDisposable und nullisieren Payload-Puffer
[SEC-KE-000] KeyExportPolicy Governance (F6)
KeyExportPolicy Enum: AllowExplicit | DenyByDefault | Prohibited
DefaultPolicyForProfile:
  - Dev → AllowExplicit
  - Staging → DenyByDefault
  - Prod → Prohibited
Enforcement:
  - BouncyCastleKeyImportExportService: expliziter `switch` mit fail-closed `default` für unbekannte Policy-Werte
  - KeyExportPolicyEnforcer (ProviderHost-intern): zentraler Gatekeeper pro Operation
  - ProviderRpcSession: `AssertRawSecretEgressPermitted` prüft `SupportsRawSecretEgress`
Public-Key-Export ist nicht policy-gated (öffentlich)

[SEC-EG-000] Handle-Only Secret Egress (F7)
Invariante: Geheimes Schlüsselmaterial verlässt die lokale Provider-Schicht nur per Handle.
Durchsetzung:
  - KEM: GenerateKeyPair/Encapsulate/Decapsulate → PrivateKeyHandle/SharedSecretHandle
  - AEAD: GenerateKey → SecretKeyHandle, Encrypt/Decrypt per SecretKeyHandle
  - KDF: DeriveKey → SecretKeyHandle (Input per SharedSecretHandle)
  - Signature: GenerateKeyPair → PrivateKeyHandle, Sign per PrivateKeyHandle
  - Export: nur via IKeyExportService.ExportPrivateKey, gated durch KeyExportPolicy
OOP-Messages transportieren Handles, nicht rohe Bytes für Secret Keys/Shared Secrets.
Raw secret egress ist per `SupportsRawSecretEgress=false` auf Provider-Envelope-Ebene sperrbar.

[FIPS-000] FIPS Boundary & Enforcement
Boundary: Provider Process (oder HSM)
Core: kein raw secret access, nur handles
FIPS filtering als Compliance-Decorator
Fail-closed wenn FIPS aktiv und keine FIPS-approved Algorithmen verfügbar
OSS Bouncy Castle ist kein FIPS boundary path
[SEC-AUD-000] Logging & Observability
ILogger<T> wird in den folgenden Kernkomponenten injiziert:
CybersuiteRuntime (init, reuse, shutdown, compliance rejection)
ProviderHost (discovery, trust, registration)
DefaultProviderTrustEvaluator (accept/reject decisions)
PolicyLoader (static class, optionaler ILogger?: parse, verify, snapshot)

Invarianten:
NullLogger-Fallback: alle Komponenten funktionieren ohne Logger
Keine Secrets in Logs: getestet via LoggingBehaviorTests
Handle128.ToString() gibt "REDACTED" zurück
RuntimeAuditEvent darf keine Secrets enthalten

[SEC-AUD-001] NativeCurveP384 (OS-native ECDH)
SC-002: NativeCurveP384 ist eine Alternative zu BouncyCastleCurveP384 für ECDH P-384.
Verwendet ECDiffieHellman.Create(nistP384) + DeriveRawSecretAgreement
OS-backed: CNG auf Windows, OpenSSL auf Linux
Hardware-accelerated und constant-time
Gleiche Schnittstelle (GenerateKeyPair, DeriveSharedSecret) wie BouncyCastleCurveP384
Empfohlen für produktionskritische Deployments

[SEC-AUD-002] AEAD Nonce-State-Machine
SEC-M-004: Struktureller Nonce-Reuse-Schutz via IAeadNonceStrategy:

MonotonicCounterNonceStrategy
Format: [4-byte random prefix] [8-byte big-endian counter]
Thread-safe via Interlocked.Increment
Overflow-Guard: wirft bei Counter-Exhaustion (2^63)
Prefix-Zeroization bei Dispose

RandomNonceStrategy
CSPRNG-basiert via RandomNumberGenerator
Birthday-Bound Collision-Tracking
Default-Threshold: 2^32 (P(collision) ≈ 2^-32)
Wirft bei Threshold-Überschreitung

Integration: AeadNonceExtensions.EncryptWithStrategy Extension-Method
Nicht-invasiv: bestehende IAeadService.Encrypt-Signatur bleibt unverändert

[SEC-AUD-003] Zertifikats-Expiry-Check
SEC-M-006: X509PolicySignatureVerifier prüft NotBefore/NotAfter explizit vor der Chain-Validierung.
Damit werden abgelaufene Zertifikate auch im Dev-Modus (AllowUntrustedChainInDevOnly) abgelehnt.

[CHG-000] Change Log
2026-02-26: AC-0.6.1 initialisiert
2026-02-26: AC-0.7.0 Provider Portfolio/Provider Management ergänzt
2026-02-26: AC-0.7.1 Policy Schema + Signature Envelope Regeln ergänzt
2026-02-26: AC-0.8.0 Stage 3 Selection + ProviderModel konkretisiert/implementiert
2026-02-26: AC-0.9.0 Stage 4 OOP Protocol Contracts ergänzt
2026-02-26: AC-1.0.0 Stage 5 ProviderHost eingeführt
2026-02-26: AC-1.0.1 Stage 5 bereinigt
2026-02-26: AC-1.1.0 Stage 6 Runtime ergänzt
2026-02-26: AC-1.2.0 Konkrete Bouncy‑Castle‑Bindung ergänzt
2026-02-26: AC-1.3.0 Operation-level OOP-RPCs + ProviderRpcSession + konkrete BC live crypto operations ergänzt
2026-02-26: AC-1.4.0 PQC/ML Architektur-Delta konkretisiert
2026-02-26: AC-1.5.0 ProviderModel + Compliance + BC ML live binding ergänzt
2025-07-17: AC-1.6.0 Security-Audit komplett, Logging, NativeCurveP384, Nonce-Strategy, KeyImport/Export, SecretBytes, Cert-Expiry
2026-03: AC-1.7.0 Thread-Safety-Hardening (Dispose-Guards, _disposed-Flag, ObjectDisposedException), Dead-Code-Bereinigung (4 verwaiste Methoden entfernt), SensitiveBufferLease (F5: ArrayPool-basierte Heap-Kopien-Reduktion mit Auto-Zeroization), KeyExportPolicy-Governance (F6: Profil-abhängige Export-Steuerung, fail-closed default), Handle-Only-Egress (F7: SupportsRawSecretEgress, AssertRawSecretEgressPermitted), SessionHandleTracker (F2: Session-bound Handle-Tracking mit DrainAll), Auto-Cleanup bei Session-Dispose (F3), Import-Zeroization (F4)