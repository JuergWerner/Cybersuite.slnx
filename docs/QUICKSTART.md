# Cybersuite — Quickstart Guide

A concise, architecture-aware guide to getting started with the Cybersuite Post-Quantum Cryptography Provider Framework on **.NET 10**.

> **Current state:** Wave 5 + Security Audit Remediation (F2–F7) — thread-safety hardening, handle-only secret egress, SensitiveBufferLease, KeyExportPolicy governance.

---

## ⚠️ Beta Software Notice

Cybersuite depends on **BouncyCastle.Cryptography 2.7.0-beta.98** (experimental pre-release).

| Suitable for                            | NOT suitable for                        |
|-----------------------------------------|-----------------------------------------|
| ✅ Research & prototyping               | ❌ Production systems                   |
| ✅ NIST FIPS 203/204 evaluation         | ❌ Critical infrastructure              |
| ✅ PQC algorithm testing                | ❌ Real-world encryption of sensitive data |
| ✅ Architecture & integration studies   | ❌ Compliance-regulated environments    |

See [BETA-WARNING.md](BETA-WARNING.md) for the full risk assessment.

---

## 1. Prerequisites

| Requirement            | Version                      |
|------------------------|------------------------------|
| .NET SDK               | **10.0** or later            |
| OS                     | Windows, Linux, or macOS     |
| IDE (optional)         | Visual Studio 2026 / VS Code / Rider |

---

## 2. Clone, Build & Test

```bash
git clone https://github.com/JuergWerner/Cybersuite.git
cd Cybersuite

dotnet build        # builds all 14 projects
dotnet test         # runs 200+ unit/integration/compliance/property tests
```

### Download NIST Test Vectors (optional)

```powershell
cd tests/TestVectors/ML-KEM
./download-vectors.ps1
cd ../../..
```

---

## 3. Solution Structure

```
Cybersuite/
├── src/
│   ├── Cybersuite.Abstractions       # Core types: AlgorithmId, SecurityStrength, ICryptoService, IPolicy
│   ├── Cybersuite.OopProtocol        # Out-of-Process wire protocol (handshake, messages, handles)
│   ├── Cybersuite.ProviderModel      # Provider metadata, compliance envelopes, trust/attestation enums
│   ├── Cybersuite.Selection          # Deterministic, fail-closed algorithm selection engine
│   ├── Cybersuite.Policy             # Policy JSON loading, SHA-384 hashing, signature verification
│   ├── Cybersuite.Compliance         # Dual compliance gate (algorithm + provider boundary admission)
│   ├── Cybersuite.ProviderHost       # Discovery → trust → launch → handshake → capability negotiation
│   └── Cybersuite.Runtime            # Top-level orchestrator: CybersuiteRuntime, RuntimeScope, audit
├── providers/
│   ├── Cybersuite.Provider.BouncyCastle         # In-process BouncyCastle backend (PQC + classical)
│   └── Cybersuite.Provider.BouncyCastle.Worker  # Out-of-process worker (classical-only, Staging/Prod)
├── tests/
│   ├── Cybersuite.Tests.Unit           # 200+ unit tests (incl. thread-safety & egress guard tests)
│   ├── Cybersuite.Tests.Integration    # Live crypto round-trip tests
│   ├── Cybersuite.Tests.Compliance     # Compliance gate tests
│   └── Cybersuite.Test.Property        # Property-based tests
├── policies/
│   ├── sample.policy.json              # Development PQM default policy
│   └── development-pqm.policy.json     # Identical PQM template for explicit use
└── docs/
    ├── Quickstart.md                   # ← you are here
    ├── ARCHITECTURE_CANON.md           # Canonical architecture reference
    └── BETA-WARNING.md                 # Beta risk assessment
```

### Layered Architecture (bottom → top)

```
 Application
     │
 Cybersuite.Runtime            ← top-level orchestrator
     │
 Cybersuite.Compliance         ← dual compliance gate (algorithm + boundary)
     │
 Cybersuite.ProviderHost       ← discovery / trust / launch / handshake / registry
     │
 Cybersuite.OopProtocol        ← wire protocol (Handle128, headers, messages)
     │
 Cybersuite.ProviderModel      ← provider descriptors, compliance envelopes, enums
     │
 Cybersuite.Selection          ← deterministic algorithm selector
 Cybersuite.Policy             ← policy loading, canonicalization, signatures
     │
 Cybersuite.Abstractions       ← AlgorithmId, SecurityStrength, ICryptoService, IPolicy
     │
 Cybersuite.Provider.BouncyCastle  ← concrete backend (ML-KEM, ML-DSA, ECDH, AES-GCM, …)
```

---

## 4. Supported Algorithms

### Post-Quantum (NIST FIPS 203 / 204)

| Algorithm      | Category          | Security Level | Strength (bits) |
|----------------|-------------------|:--------------:|:---------------:|
| ML-KEM-512     | KeyEncapsulation  | 1              | 128             |
| **ML-KEM-768** | KeyEncapsulation  | 3              | **192** ⭐       |
| ML-KEM-1024    | KeyEncapsulation  | 5              | 256             |
| ML-DSA-44      | Signature         | 2              | 128             |
| **ML-DSA-65**  | Signature         | 3              | **192** ⭐       |
| ML-DSA-87      | Signature         | 5              | 256             |

### Classical

| Algorithm       | Category          | Strength (bits) |
|-----------------|-------------------|:---------------:|
| ECDH-P384-KEM   | KeyEncapsulation  | 192             |
| ECDSA-P384      | Signature         | 192             |
| AES-256-GCM     | SymmetricAead     | 256             |
| HKDF-SHA384     | KeyDerivation     | 192             |

> ⭐ **Recommended defaults** — the Development PQM policy pins ML-KEM-768 and ML-DSA-65 to the BouncyCastle provider.

---

## 5. Quick Example: Low-Level Provider Connection

The fastest way to run cryptographic operations is via a direct `BouncyCastleProviderConnection`. This bypasses policy/compliance/runtime and talks to the provider at the OOP protocol level.

```csharp
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;

// 1. Create the in-process provider package (Development PQM default)
string entrypoint = typeof(BouncyCastleProviderConnection).Assembly.Location;
string root = Path.GetDirectoryName(entrypoint)!;
var package = BouncyCastleManifestFactory.CreateDevelopmentPqmPackage(root, entrypoint);

// 2. Open the provider connection
await using var conn = new BouncyCastleProviderConnection(package);

// 3. Perform OOP handshake
byte[] nonce = new byte[OopConstants.NonceSizeBytes];
RandomNumberGenerator.Fill(nonce);

var clientHello = new ClientHello(
    ProtocolVersion.V1_0, nonce, new byte[48],
    ExecutionProfile.Dev, fipsRequired: false,
    experimentalAllowed: true, tenantId: null,
    expectedProviderId: null, expectedBuildHash: null);

ProviderHello providerHello = await conn.HandshakeAsync(clientHello, CancellationToken.None);

byte[] transcript = HandshakeTranscript.ComputeTranscriptHashSha384(clientHello, providerHello);
byte[] channelBinding = HandshakeTranscript.ComputeChannelBindingSha384(transcript);

// 4. Helper: create channel-bound, replay-resistant request headers
ulong counter = 0;
OopRequestHeader Header(OopMessageType type) =>
    new(ProtocolVersion.V1_0, type, Handle128.NewRandom(), ++counter, channelBinding);

// 5. ML-KEM-768: generate key pair → encapsulate → decapsulate
var algId = new AlgorithmId("ML-KEM-768");

var genResp = await conn.KemGenerateKeyPairAsync(
    new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), algId),
    CancellationToken.None);

Console.WriteLine($"Public Key : {genResp.KeyPair.PublicKey.Length} bytes");

var encResp = await conn.KemEncapsulateAsync(
    new KemEncapsulateRequest(
        Header(OopMessageType.KemEncapsulateRequest), algId,
        genResp.KeyPair.PublicKey),
    CancellationToken.None);

Console.WriteLine($"Ciphertext : {encResp.Result.Ciphertext.Length} bytes");

var decResp = await conn.KemDecapsulateAsync(
    new KemDecapsulateRequest(
        Header(OopMessageType.KemDecapsulateRequest), algId,
        genResp.KeyPair.PrivateKey, encResp.Result.Ciphertext.Span),
    CancellationToken.None);

Console.WriteLine($"Shared Secret established (Handle: {decResp.SharedSecret.Value})");
```

**Expected output:**

```
Public Key : 1184 bytes
Ciphertext : 1088 bytes
Shared Secret established (Handle: ...)
```

---

## 6. ML-DSA Digital Signatures

```csharp
var algId = new AlgorithmId("ML-DSA-65");

// Generate signing key pair
var keyPair = await conn.SignatureGenerateKeyPairAsync(
    new SignatureGenerateKeyPairRequest(Header(OopMessageType.SignatureGenerateKeyPairRequest), algId),
    CancellationToken.None);

// Sign a document
byte[] document = File.ReadAllBytes("document.pdf");
var signResp = await conn.SignatureSignAsync(
    new SignatureSignRequest(
        Header(OopMessageType.SignatureSignRequest), algId,
        keyPair.KeyPair.PrivateKey, document),
    CancellationToken.None);

// Verify the signature
var verifyResp = await conn.SignatureVerifyAsync(
    new SignatureVerifyRequest(
        Header(OopMessageType.SignatureVerifyRequest), algId,
        keyPair.KeyPair.PublicKey, document, signResp.Signature.ToArray()),
    CancellationToken.None);

Console.WriteLine($"Signature valid: {verifyResp.IsValid}");
```

---

## 7. Hybrid KEM (ECDH + ML-KEM)

Combine classical and post-quantum key exchange for defense-in-depth during the transition period:

```csharp
var ecdhAlg  = new AlgorithmId("ECDH-P384-KEM");
var mlkemAlg = new AlgorithmId("ML-KEM-768");

// Classical ECDH key exchange
var ecdhKeyPair = await conn.KemGenerateKeyPairAsync(
    new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), ecdhAlg),
    CancellationToken.None);
var ecdhEncap = await conn.KemEncapsulateAsync(
    new KemEncapsulateRequest(Header(OopMessageType.KemEncapsulateRequest), ecdhAlg, ecdhKeyPair.KeyPair.PublicKey),
    CancellationToken.None);

// Post-quantum ML-KEM key exchange
var mlkemKeyPair = await conn.KemGenerateKeyPairAsync(
    new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), mlkemAlg),
    CancellationToken.None);
var mlkemEncap = await conn.KemEncapsulateAsync(
    new KemEncapsulateRequest(Header(OopMessageType.KemEncapsulateRequest), mlkemAlg, mlkemKeyPair.KeyPair.PublicKey),
    CancellationToken.None);

// Combine both secrets via HKDF
var kdfAlg = new AlgorithmId("HKDF-SHA384");
var combined = await conn.KdfDeriveKeyAsync(
    new KdfDeriveKeyRequest(Header(OopMessageType.KdfDeriveKeyRequest), kdfAlg,
        inputKeyMaterial: mlkemEncap.Result.SharedSecret,
        salt: ecdhEncap.Result.SharedSecret,
        info: "hybrid-kem"u8.ToArray(),
        outputLength: 32),
    CancellationToken.None);

Console.WriteLine("Hybrid shared secret established!");
```

---

## 8. Full-Stack Example: Runtime with Policy, Selection & Compliance

The architecture-recommended path uses `CybersuiteRuntime`, which orchestrates the full pipeline:
**policy loading → provider discovery → trust evaluation → launch → handshake → capability negotiation → deterministic selection → compliance validation**.

```csharp
using Cybersuite.Abstractions;
using Cybersuite.Compliance;
using Cybersuite.Policy;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Discovery;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.Runtime;
using Cybersuite.Selection;

// ── 1. Load and validate policy ──────────────────────────────────────
// Option A: from JSON file
PolicyLoadOptions loadOptions = PolicyLoadOptions.CreateDevRelaxed();
PolicySnapshot policy = PolicyLoader.LoadFromFile("policies/sample.policy.json", loadOptions);

// Option B: from code defaults (produces the same Development PQM snapshot)
// PolicySnapshot policy = PolicyDefaults.CreateDevelopmentPqm();

// ── 2. Create the BouncyCastle provider package ──────────────────────
string entrypoint = typeof(BouncyCastleProviderConnection).Assembly.Location;
string root = Path.GetDirectoryName(entrypoint)!;
ProviderPackage package = BouncyCastleManifestFactory.CreateDevelopmentPqmPackage(root, entrypoint);

// ── 3. Wire up the ProviderHost pipeline ─────────────────────────────
IProviderDiscovery discovery = new StaticProviderDiscovery(package);
IProviderTrustEvaluator trustEvaluator = new DefaultProviderTrustEvaluator();
ICapabilitySnapshotDecoder decoder = new CapabilitySnapshotDecoder();

var hostOptions = new ProviderHostOptions
{
    ExecutionProfile = ExecutionProfile.Dev
};

var providerHost = new Cybersuite.ProviderHost.ProviderHost(
    hostOptions, discovery, trustEvaluator,
    new NotImplementedProviderLauncher(),   // only needed for out-of-process providers
    decoder);

// ── 4. Create the Runtime ────────────────────────────────────────────
ISelectionEngine selector = new AlgorithmSelector();
IComplianceGate compliance = new DualComplianceGate();

await using var runtime = new CybersuiteRuntime(
    providerHost, selector, RuntimeOptions.Default, complianceGate: compliance);

// ── 5. Initialize: runs discovery → trust → launch → handshake → select
var context = new SelectionContext(
    Profile: ExecutionProfile.Dev,
    ForceFips: null,
    TenantId: "Development");

RuntimeScope scope = await runtime.InitializeAsync(policy, context, CancellationToken.None);

// ── 6. Inspect the selection plan ────────────────────────────────────
foreach (var entry in scope.SelectionPlan)
{
    Console.WriteLine($"  {entry.Key,-20} → {entry.Value.AlgorithmId.Value} " +
                      $"(provider: {entry.Value.ProviderId.Value})");
}

// ── 7. Open a provider session and perform operations ────────────────
using IProviderSession session = runtime.OpenSelectedSession(AlgorithmCategory.KeyEncapsulation);

// The session is policy-bound, compliance-gated, and channel-bound.
// Use session.GetKem(...), session.GetSignature(...), etc.

// ── 8. Shutdown ──────────────────────────────────────────────────────
await runtime.ShutdownAsync(CancellationToken.None);
```

---

## 9. Policy Anatomy

The policy JSON drives algorithm selection, provider routing, and security mode enforcement.
Both shipped sample files use the **Development PQM** profile:

```jsonc
{
  "schemaVersion": "1.0",
  "sequence": 1,                          // anti-rollback counter
  "tenantId": "Development",
  "securityMode": "Pqc",                  // Classical | Pqc | Hybrid
  "fipsRequired": false,
  "minimumStrengthByCategory": {
    "KeyEncapsulation": 192,              // bits — drives selection floor
    "Signature": 192,
    "SymmetricAead": 256,
    "KeyDerivation": 192
  },
  "providerAllowlist": ["BouncyCastle"],
  "pinnedProviderByCategory": {},
  "pinnedProviderByAlgorithm": {
    "ML-KEM-768": "BouncyCastle",         // algorithm-level pin
    "ML-DSA-65":  "BouncyCastle"
  },
  "signature": null                        // required in Staging/Prod
}
```

### Policy Loading Profiles

| Profile     | Factory method                               | Signature required | Allowlist required | Revocation |
|-------------|----------------------------------------------|:------------------:|:------------------:|:----------:|
| **Dev**     | `PolicyLoadOptions.CreateDevRelaxed()`       | ❌                 | ❌                 | NoCheck    |
| **Staging** | `PolicyLoadOptions.CreateStagingStrict(...)` | ✅                 | ✅                 | Online     |
| **Prod**    | `PolicyLoadOptions.CreateProdStrict(...)`    | ✅                 | ✅                 | Online     |

### Programmatic Default

```csharp
// Creates an identical Development PQM snapshot without reading a file
PolicySnapshot policy = PolicyDefaults.CreateDevelopmentPqm();
```

---

## 10. Trust Pipeline (Wave 1–5)

Every provider traverses a multi-gate trust pipeline before it is admitted to the registry:

```
 ProviderPackage
     │
     ▼
 ① Profile-Aware Allowlist ─── empty allowlist in Prod → reject
     │
     ▼
 ② SHA-256 Entrypoint Hash ── constant-time comparison (FixedTimeEquals)
     │
     ▼
 ③ Structured Release Bundle ── (Wave 5) repository/channel/SBOM/manifest digests
     │
     ▼
 ④ Structured Provenance ───── (Wave 4) identity/boundary/signer/expiry
     │
     ▼
 ⑤ OOP Handshake ──────────── ClientHello ↔ ProviderHello, transcript hash
     │
     ▼
 ⑥ Structured Attestation ──── (Wave 4) self-attestation evidence in handshake
     │
     ▼
 ⑦ Capability Negotiation ──── hash binding, transport budget, boundary check
     │
     ▼
 ProviderRecord in Registry
```

Any gate failure returns a **fail-closed** decision with a diagnostic reason code.

---

## 11. Execution Profiles & Boundary Classes

| Profile     | RequiredBoundaryClass | Experimental allowed | Provenance required | Release bundle required |
|-------------|:---------------------:|:--------------------:|:-------------------:|:-----------------------:|
| **Dev**     | None                  | ✅                   | ❌                  | ❌                      |
| **Staging** | IsolatedProcess       | ❌                   | ✅                  | ✅                      |
| **Prod**    | IsolatedProcess       | ❌                   | ✅                  | ✅                      |

> **Note:** A true `ValidatedBoundary` (FIPS) provider path is planned but not yet active.

---

## 12. Running Tests

```bash
# All tests (unit + integration + compliance + property)
dotnet test

# Only unit tests
dotnet test --filter "Project=Cybersuite.Tests.Unit"

# Only compliance tests
dotnet test --filter "Project=Cybersuite.Tests.Compliance"

# A specific test by name
dotnet test --filter "FullyQualifiedName~MlKem_FullRoundTrip"

# ML-KEM NIST test vectors
dotnet test --filter "FullyQualifiedName~MlKemTestVectorTests"
```

---

## 13. Key Concepts for Developers

### Handle-Based Secret Management

Secret key material never leaves the provider boundary as raw bytes. Instead, the protocol returns opaque **handles** (`PrivateKeyHandle`, `SecretKeyHandle`, `SharedSecretHandle`) backed by `Handle128`. Always destroy handles after use:

```csharp
// After using a shared secret handle
session.Destroy(sharedSecretHandle);
```

**Dispose guards:** All store operations throw `ObjectDisposedException` if the store has been disposed. Double-dispose is safe (idempotent).

### SensitiveBufferLease (Pooled Secret Buffers)

For internal operations that need temporary access to secret bytes, `SensitiveBufferLease` provides an `ArrayPool<byte>`-backed buffer with automatic zeroization on `Dispose()`:

```csharp
using var lease = store.LeaseSecretKey(handle);
// lease.ReadOnlySpan provides read-only access
// On Dispose → CryptographicOperations.ZeroMemory + pool return
```

### KeyExportPolicy

Private key export is governed by a per-profile policy:

| Profile     | Default Policy     | Behavior                                |
|-------------|--------------------|-----------------------------------------|
| **Dev**     | `AllowExplicit`    | Export allowed, must be explicit         |
| **Staging** | `DenyByDefault`    | Export denied unless override granted    |
| **Prod**    | `Prohibited`       | Export unconditionally blocked           |

Unknown policy values are rejected fail-closed. Public key export is never gated.

### Nonce Safety

AEAD operations use structural nonce-reuse prevention via `IAeadNonceStrategy`:

```csharp
// Monotonic counter (recommended for streaming)
var strategy = new MonotonicCounterNonceStrategy(nonceSize: 12);

// Random nonce (suitable for few messages per key)
var strategy = new RandomNonceStrategy(nonceSize: 12);
```

### Immutability & Thread Safety

- `PolicySnapshot`, `ProviderRegistrySnapshot`, `RuntimeScope` are **immutable** and thread-safe.
- `BouncyCastleKeyMaterialStore` uses `lock(_gate)` + a `_disposed` flag with `ObjectDisposedException` on all 12 public methods.
- `SessionHandleTracker` uses `lock(_gate)` with `DrainAll` semantics for session cleanup.
- `LiveProviderSessionState` uses a provider-local operation gate for synchronized access.
- `ProviderRegistry` uses `ImmutableInterlocked` for lock-free concurrent reads.
- `SensitiveBufferLease` uses `Interlocked.Exchange` for thread-safe dispose.
- `ProviderRpcSession` + all proxies use `Interlocked.CompareExchange` for dispose guards.
- Concurrency is validated by 10 dedicated thread-safety tests (parallel add/lease/destroy, dispose races).

### SecretBytes Auto-Zeroization

Use `SecretBytes` for sensitive data that should be zeroed from memory automatically:

```csharp
using var secret = new SecretBytes(rawKeyMaterial);
// secret.Span is available here
// On Dispose → CryptographicOperations.ZeroMemory is called
```

---

## 14. Performance Tips

1. **Destroy handles** promptly after use — prevents secret material accumulation
2. **Reuse provider sessions** where possible instead of opening new ones per operation
3. **Use `ValueTask`-based** async APIs for hot-path operations
4. **Parallelize** independent key generations across categories
5. **Use `IAeadNonceStrategy`** for structural nonce-reuse prevention
6. **Prefer `ExportPrivateKeySecure`** over `ExportPrivateKey` for auto-zeroization
7. **Cache `PolicySnapshot`** — it is immutable and thread-safe

---

## 15. Troubleshooting

### Build fails with CS0006 or missing references

```bash
dotnet restore
dotnet build
```

### "Type not found" for BouncyCastle types

Ensure the pre-release package is restored:

```bash
dotnet add package BouncyCastle.Cryptography --version 2.7.0-beta.98
```

### "Test vectors not found"

```powershell
cd tests/TestVectors/ML-KEM
./download-vectors.ps1
```

### "Unknown AlgorithmCategory" in policy parsing

Policy JSON keys use **PascalCase** (`KeyEncapsulation`, not `keyEncapsulation`).
The `PolicyJsonParser` is case-sensitive by design — see `ParseCategory()`.

### Staging/Prod policy loading fails

Non-Dev profiles require:
1. An `IPolicySignatureVerifier` (e.g., `X509PolicySignatureVerifier`)
2. A non-empty provider allowlist
3. Online certificate revocation checking (`X509RevocationMode.Online`)

Use `PolicyLoadOptions.CreateStagingStrict(verifier)` or `CreateProdStrict(verifier)`.

### Connection timeout

```csharp
// Increase timeout for slow environments
var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
await conn.KemGenerateKeyPairAsync(..., cts.Token);
```

---

## 16. Further Reading

| Document                                                   | Description                                    |
|------------------------------------------------------------|------------------------------------------------|
| [ARCHITECTURE.md](../ARCHITECTURE.md)                      | Full Wave 1–5 architecture status              |
| [ARCHITECTURE_CANON.md](ARCHITECTURE_CANON.md)             | Canonical architecture reference               |
| [BETA-WARNING.md](BETA-WARNING.md)                         | Risk assessment and limitations                |
| [README.md](../README.md)                                  | Project overview, benchmarks, full API surface  |
| [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM standard                                |
| [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) | ML-DSA standard                                |
| [BouncyCastle C#](https://github.com/bcgit/bc-csharp)      | BouncyCastle cryptographic library             |

---

*Last updated for Wave 5 + Security Audit Remediation — AC-1.7.0*