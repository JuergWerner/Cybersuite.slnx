# Cybersuite - Post-Quantum Cryptography Provider Framework

[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue.svg)](https://dotnet.microsoft.com/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![FIPS 203](https://img.shields.io/badge/FIPS%20203-ML--KEM-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![FIPS 204](https://img.shields.io/badge/FIPS%20204-ML--DSA-green.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![BouncyCastle](https://img.shields.io/badge/BouncyCastle-2.7.0--beta.98-orange.svg)](https://github.com/bcgit/bc-csharp)

---

## ⚠️ WICHTIGER HINWEIS: Beta-Software

**Diese Suite verwendet experimentelle Beta-Software (BouncyCastle 2.7.0-beta.98) und ist NICHT für Production-Umgebungen geeignet.**

✅ **Geeignet für:**
- Forschung & Entwicklung
- Post-Quantum Cryptography Prototyping
- Testing gegen NIST FIPS 203/204 Standards
- Evaluation von ML-KEM und ML-DSA

❌ **NICHT verwenden für:**
- Production-Systeme
- Kritische Infrastruktur
- Produktive Verschlüsselung sensibler Daten

📋 Details siehe [Sicherheitsüberlegungen](#sicherheitsüberlegungen)

## Default-Profil (Wave 5)

- **Default Sample Policy:** `policies/sample.policy.json` ist jetzt auf **Development PQM** gesetzt.
- **Default PQM Helper:** `PolicyDefaults.CreateDevelopmentPqm()` erzeugt denselben Grundzustand im Code.
- **Default Dev Package:** `BouncyCastleManifestFactory.CreateDevelopmentPqmPackage(...)` startet den Dev-/Reference-Pfad mit experimentellem PQC-Katalog.

## Boundary-Truth-Status (Wave 5)

- **active:** `ReferenceInProcess`-Pfad für `Dev` mit BouncyCastle-In-Process-Provider (klassisch + experimentelle PQC-Algorithmen)
- **active:** `ProductionIsolated`-Pfad für `Staging`/`Prod` über separaten Worker-Prozess mit klassischem Stable-Subset
- **partial:** strukturierte Provenance- und Self-Attestation-Prüfung; keine Aussage über hardware-backed Attestation
- **active:** strukturierte Release-Bundle-Prüfung ausserhalb `Dev` (Repository/Channel + Release-Manifest-/SBOM-Digests)
- **planned:** validierte/FIPS-Boundary, Chunking-/Streaming-Transport und vollständige externe CI/SLSA-Pipeline

---

## Überblick

**Cybersuite** ist ein modernes, hochsicheres kryptografisches Framework für .NET 10, das klassische und post-quantenkryptografische (PQC) Algorithmen über eine einheitliche Abstraktionsschicht bereitstellt. Die Suite wurde speziell entwickelt, um den NIST FIPS 203 (ML-KEM) und FIPS 204 (ML-DSA) Standards zu entsprechen und gleichzeitig maximale Flexibilität durch ein Provider-basiertes Architekturmodell zu bieten.

### Hauptmerkmale

- ✅ **Post-Quantum Cryptography (PQC)**: Vollständige Unterstützung für ML-KEM und ML-DSA
- 🔐 **Klassische Kryptografie**: ECDH, ECDSA, AES-GCM, HKDF
- 🏗️ **Provider-Architektur**: Pluggable Backend-Implementierungen
- 🔒 **Out-of-Process Execution**: Sichere Isolation kritischer Operationen
- ✨ **API-Version-Agnostisch**: Reflection-basierte Kompatibilität
- 📊 **NIST Test Vectors**: Validierung gegen offizielle Testdaten
- 🧪 **Umfassende Tests**: 162 Tests (Unit, Integration, Compliance, Property)
- 📋 **Structured Logging**: `ILogger<T>` mit NullLogger-Fallback, keine Secret-Leaks
- 🔑 **Key-Import/Export**: `IKeyImportService`/`IKeyExportService` mit `SecretBytes`-Auto-Zeroization
- 🛡️ **Nonce-Safety**: Strukturelle Nonce-Reuse-Prävention via `IAeadNonceStrategy`
- ⚡ **OS-native ECDH**: `NativeCurveP384` — constant-time, hardware-accelerated

---

## Architektur

### Schichtenmodell

```
┌─────────────────────────────────────────────────────────┐
│              Application Layer                           │
│  (Benutzeranwendungen, Services, APIs)                  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Cybersuite.Runtime                             │
│  (Top-Level Orchestrierung, Audit, RuntimeScope)        │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Cybersuite.Compliance                          │
│  (Compliance-Gates, DualComplianceGate)                 │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Cybersuite.ProviderHost                        │
│  (Provider Discovery, Trust, Launch, Handshake)         │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Cybersuite.OopProtocol                         │
│  (Out-of-Process Kommunikationsprotokoll)               │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Cybersuite.ProviderModel                       │
│  (Provider-Deskriptoren, Isolationsmodi)                │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Cybersuite.Selection / Cybersuite.Policy                │
│  (Algorithmen-Auswahl, Policy-Validierung)              │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│           Cybersuite.Abstractions                        │
│  (AlgorithmId, SecurityStrength, ICryptoService)        │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│     Cybersuite.Provider.BouncyCastle                     │
│  (BouncyCastle-Backend mit PQC-Unterstützung)           │
└─────────────────────────────────────────────────────────┘
```

### Kernkomponenten

#### 1. **Cybersuite.Abstractions**
Definiert die kryptografischen Basis-Typen und Schnittstellen:
- `AlgorithmId` - Stark typisierter, unveränderlicher Algorithmen-Bezeichner
- `SecurityStrength` - Sicherheitsstärke-Metrik (in Bits)
- `ICryptoService` - Basis-Service-Vertrag für alle kryptografischen Operationen
- `IProviderSession` - Sitzungsbindung an einen konkreten Provider

#### 2. **Cybersuite.OopProtocol**
Implementiert ein sicheres, versioniertes Kommunikationsprotokoll für Out-of-Process Provider:
- Handshake mit Capability Negotiation
- Channel Binding für Replay-Schutz
- Request/Response Message Handling
- Handle-basierte Ressourcenverwaltung

#### 3. **Cybersuite.ProviderHost**
Verwaltet Provider-Instanzen und Connections:
- Provider Package Loading
- Connection Lifecycle Management
- Resource Cleanup

#### 4. **Cybersuite.Provider.BouncyCastle**
BouncyCastle-basierte Implementierung mit zwei klar getrennten Pfaden:
- **Dev / ReferenceInProcess:** klassisch + experimentelle PQC-Unterstützung
- **Staging / Prod / ProductionIsolated:** klassisches Stable-Subset über Worker-Prozess
- Klassische Kryptografie (ECDH, ECDSA, AES, HKDF)
- Deterministische und nicht-deterministische Modi

---

## Unterstützte Algorithmen

### Post-Quantum Cryptography (PQC)

#### ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) - FIPS 203
- **ML-KEM-512** - Sicherheitsstufe 1 (~128-bit klassisch)
- **ML-KEM-768** - Sicherheitsstufe 3 (~192-bit klassisch)
- **ML-KEM-1024** - Sicherheitsstufe 5 (~256-bit klassisch)

**Operationen:**
- Key Pair Generation
- Encapsulation (generiert Ciphertext und Shared Secret)
- Decapsulation (rekonstruiert Shared Secret aus Ciphertext)

#### ML-DSA (Module-Lattice-Based Digital Signature Algorithm) - FIPS 204
- **ML-DSA-44** - Sicherheitsstufe 2
- **ML-DSA-65** - Sicherheitsstufe 3
- **ML-DSA-87** - Sicherheitsstufe 5

**Operationen:**
- Key Pair Generation
- Sign (deterministisch und nicht-deterministisch)
- Verify

### Klassische Kryptografie

#### Key Encapsulation
- **ECDH-P384-KEM** - Elliptic Curve Diffie-Hellman KEM (NIST P-384 Kurve)

#### Digitale Signaturen
- **ECDSA-P384** - Elliptic Curve Digital Signature Algorithm (NIST P-384)

#### Verschlüsselung
- **AES-256-GCM** - Advanced Encryption Standard mit Galois/Counter Mode

#### Key Derivation
- **HKDF-SHA384** - HMAC-based Key Derivation Function mit SHA-384

---

## Installation & Setup

### Voraussetzungen

- **.NET 8 SDK** oder höher
- **Visual Studio 2022** oder **VS Code** mit C# Extension
- **PowerShell 7+** (für Skripte)

### NuGet-Pakete

⚠️ **WICHTIG: Beta-Version erforderlich**

Cybersuite benötigt die **Beta-Version** von BouncyCastle.Cryptography für vollständige ML-KEM und ML-DSA Unterstützung mit BouncyCastle 2.0+ API.

```xml
<ItemGroup>
  <PackageReference Include="BouncyCastle.Cryptography" Version="2.7.0-beta.98" />
</ItemGroup>
```

**Hinweise zur Beta-Version:**
- ✅ Enthält vollständige FIPS 203 (ML-KEM) und FIPS 204 (ML-DSA) Implementierungen
- ⚠️ Beta-Status: API kann sich noch ändern
- ⚠️ Nicht für Production-Umgebungen empfohlen (Stand: März 2026)
- 🔄 Aktualisieren Sie regelmäßig auf neuere Beta-Versionen
- 📋 Überwachen Sie [BouncyCastle Release Notes](https://github.com/bcgit/bc-csharp/releases)

**Stable Release verwenden (wenn verfügbar):**
```bash
# Überprüfen Sie, ob BouncyCastle 2.4+ stable verfügbar ist
dotnet list package --outdated
```

### Projekt-Struktur

```
Cybersuite/
├── src/
│   ├── Cybersuite.Abstractions/       # Kryptografische Schnittstellen & Basis-Typen
│   ├── Cybersuite.Policy/             # Policy-Laden, Validierung, Signaturen
│   ├── Cybersuite.Selection/          # Algorithmen-Auswahl bei Policy-Verstoß
│   ├── Cybersuite.ProviderModel/      # Provider-Deskriptoren & Isolationsmodi
│   ├── Cybersuite.OopProtocol/        # Out-of-Process Protokoll
│   ├── Cybersuite.ProviderHost/       # Provider Discovery, Trust, Launch
│   ├── Cybersuite.Compliance/         # Compliance-Gates & Dual-Prüfung
│   └── Cybersuite.Runtime/            # Top-Level Orchestrierung & Audit
├── providers/
│   └── Cybersuite.Provider.BouncyCastle/  # BouncyCastle-Backend (PQC + klassisch)
├── tests/
│   ├── Cybersuite.Tests.Unit/         # Unit Tests
│   ├── Cybersuite.Tests.Property/     # Property-Based Tests
│   ├── Cybersuite.Tests.Compliance/   # Compliance Tests
│   ├── Cybersuite.Tests.Integration/  # Integration Tests
│   └── TestVectors/                   # NIST Test Vectors
│       └── ML-KEM/
│           ├── download-vectors.ps1   # Download-Script
│           ├── README.md              # Test Vector Dokumentation
│           ├── ML-KEM-512/
│           ├── ML-KEM-768/
│           └── ML-KEM-1024/
└── docs/                              # Dokumentation
```

---

## Verwendung

### 1. Provider-Verbindung erstellen

```csharp
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Cybersuite.Policy;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;

// Provider Package erstellen
string entrypoint = typeof(BouncyCastleProviderConnection).Assembly.Location;
string root = Path.GetDirectoryName(entrypoint)!;
var pkg = BouncyCastleManifestFactory.CreateDevelopmentPqmPackage(root, entrypoint);

// Development-PQM-Policy (optional, wenn Sie den Runtime/Policy-Pfad nutzen)
var policy = PolicyDefaults.CreateDevelopmentPqm();

// Connection initialisieren
await using var connection = new BouncyCastleProviderConnection(pkg);

// Handshake durchführen
var nonce = new byte[OopConstants.NonceSizeBytes];
RandomNumberGenerator.Fill(nonce);

var clientHello = new ClientHello(
    ProtocolVersion.V1_0, 
    nonce, 
    new byte[48],
    ExecutionProfile.Dev, 
    false, 
    true, 
    null, 
    null, 
    null);

var providerHello = await connection.HandshakeAsync(clientHello, CancellationToken.None);
```

### 2. ML-KEM Key Encapsulation

```csharp
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Messages;

var algId = new AlgorithmId("ML-KEM-768");

// Key Pair generieren
var genResp = await connection.KemGenerateKeyPairAsync(
    new KemGenerateKeyPairRequest(header, algId),
    CancellationToken.None);

var publicKey = genResp.KeyPair.PublicKey;
var privateKey = genResp.KeyPair.PrivateKey;

// Encapsulation (Sender-Seite)
var encResp = await connection.KemEncapsulateAsync(
    new KemEncapsulateRequest(header, algId, publicKey),
    CancellationToken.None);

var ciphertext = encResp.Result.Ciphertext;
var sharedSecretHandle = encResp.Result.SharedSecret;

// Decapsulation (Empfänger-Seite)
var decResp = await connection.KemDecapsulateAsync(
    new KemDecapsulateRequest(header, algId, privateKey, ciphertext.Span),
    CancellationToken.None);

var recoveredSecretHandle = decResp.SharedSecret;
```

### 3. ML-DSA Digitale Signaturen

```csharp
var algId = new AlgorithmId("ML-DSA-65");

// Key Pair generieren
var genResp = await connection.SignatureGenerateKeyPairAsync(
    new SignatureGenerateKeyPairRequest(header, algId),
    CancellationToken.None);

byte[] message = "Wichtige Nachricht"u8.ToArray();

// Signieren
var signResp = await connection.SignatureSignAsync(
    new SignatureSignRequest(header, algId, genResp.KeyPair.PrivateKey, message),
    CancellationToken.None);

var signature = signResp.Signature;

// Verifizieren
var verifyResp = await connection.SignatureVerifyAsync(
    new SignatureVerifyRequest(header, algId, genResp.KeyPair.PublicKey, message, signature.Span),
    CancellationToken.None);

Console.WriteLine($"Signatur gültig: {verifyResp.IsValid}");
```

### 4. AES-256-GCM Verschlüsselung

```csharp
var algId = new AlgorithmId("AES-256-GCM");
var key = new byte[32]; // 256-bit Key
var nonce = new byte[12]; // 96-bit Nonce
RandomNumberGenerator.Fill(key);
RandomNumberGenerator.Fill(nonce);

var keyHandle = await connection.ImportSecretKeyAsync(...);

byte[] plaintext = "Geheimer Text"u8.ToArray();
byte[] associatedData = "Metadata"u8.ToArray();

// Verschlüsseln
var encResp = await connection.AeadEncryptAsync(
    new AeadEncryptRequest(header, algId, keyHandle, nonce, plaintext, associatedData),
    CancellationToken.None);

var ciphertext = encResp.Ciphertext;

// Entschlüsseln
var decResp = await connection.AeadDecryptAsync(
    new AeadDecryptRequest(header, algId, keyHandle, nonce, ciphertext.Span, associatedData),
    CancellationToken.None);

var recoveredPlaintext = decResp.Plaintext;
```

---

## NIST Test Vector Validation

Cybersuite enthält eine umfassende Test-Infrastruktur zur Validierung gegen offizielle NIST FIPS 203 Test-Vektoren.

### Test-Vektoren herunterladen

```powershell
cd tests\TestVectors\ML-KEM
.\download-vectors.ps1
```

Das Script lädt automatisch:
- **keyGen.json** - Test-Vektoren für Schlüsselgenerierung
- **encapDecap.json** - Test-Vektoren für Encapsulation/Decapsulation
- Für alle drei Parameter-Sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024)

### Tests ausführen

```bash
dotnet test tests/Cybersuite.Tests.Integration/Cybersuite.Tests.Integration.csproj --filter "FullyQualifiedName~MlKemTestVectorTests"
```

**Verfügbare Tests:**
- `KeyGeneration_ValidateAgainstNistVectors` - Validiert Schlüsselgenerierung (75 Tests)
- `EncapDecap_ValidateAgainstNistVectors` - Validiert Encap/Decap Roundtrips (75 Tests)

### Test-Ergebnisse

```
Test run completed. 6 tests passed, 0 failed.
- ML-KEM-512: KeyGen (25 vectors), EncapDecap (25 vectors)
- ML-KEM-768: KeyGen (25 vectors), EncapDecap (25 vectors)
- ML-KEM-1024: KeyGen (25 vectors), EncapDecap (25 vectors)
```

---

## Architektur-Details

### Reflection-basierte PQC-Unterstützung

Cybersuite verwendet Reflection, um mit verschiedenen BouncyCastle-Versionen kompatibel zu sein, da PQC-APIs in BouncyCastle 2.0+ signifikante Änderungen erfahren haben.

**Wichtige Änderungen in BouncyCastle 2.0:**

1. **Namespace Migration:**
   - Alt: `Org.BouncyCastle.Pqc.Crypto.MLKem.*`
   - Neu: `Org.BouncyCastle.Crypto.*`

2. **ML-KEM API:**
   - Neue Klassen: `MLKemGenerator`, `MLKemExtractor`
   - Constructor benötigt `MLKemParameters`
   - Array-basierte Methoden statt Span

3. **ML-DSA API:**
   - `MLDsaSigner` benötigt Parameter im Constructor
   - Neuer boolean Parameter für deterministischen Modus

**Implementierung:**

```csharp
private static Type ResolveRequiredType(string baseName)
{
    string[] namespaces = {
        "Org.BouncyCastle.Crypto.Parameters",
        "Org.BouncyCastle.Crypto.Generators",
        "Org.BouncyCastle.Crypto.Kems",
        "Org.BouncyCastle.Pqc.Crypto.MLKem"
    };
    
    foreach (var ns in namespaces)
    {
        var fullName = $"{ns}.{baseName}, BouncyCastle.Cryptography";
        var type = Type.GetType(fullName);
        if (type != null) return type;
    }
    
    throw new NotSupportedException($"Type {baseName} not found in any namespace");
}
```

### Out-of-Process Protocol

Das OOP-Protokoll ermöglicht die Ausführung kryptografischer Operationen in einem isolierten Prozess für erhöhte Sicherheit.

**Protokoll-Features:**
- **Versioning:** Protokollversion V1.0 mit Forward-Compatibility
- **Handshake:** Capability Negotiation und Channel Binding
- **Message Types:** 25+ verschiedene Request/Response-Typen
- **Handle Management:** Opaque Handles für Schlüssel und Secrets
- **Error Handling:** Strukturierte Fehler mit ErrorCode Enum

**Message Flow:**

```
Client                           Provider
  |                                 |
  |--- ClientHello ---------------->|
  |<-- ProviderHello ---------------|
  |                                 |
  |--- KemGenerateKeyPairRequest -->|
  |<-- KemGenerateKeyPairResponse --|
  |                                 |
  |--- KemEncapsulateRequest ------>|
  |<-- KemEncapsulateResponse ------|
  |                                 |
  |--- DestroyHandleRequest ------->|
  |<-- DestroyHandleResponse -------|
```

---


## Umgang mit Secret-Keys, Shared-Secrets und Private Keys

Cybersuite verwendet für sensibles Schlüsselmaterial ein **handle-basiertes Secret-Management-Modell**. Der Core arbeitet grundsätzlich nicht mit rohen Geheimnissen, sondern mit drei Handle-Typen:

- `PrivateKeyHandle` – asymmetrische private Schlüssel
- `SecretKeyHandle` – symmetrische Schlüssel (z. B. AES-256-GCM)
- `SharedSecretHandle` – KEM-/ECDH-Ergebnisse vor der Ableitung eines Arbeits-Schlüssels

Damit bleiben geheime Werte provider-seitig gekapselt, während der Core nur Referenzen über den OOP-Pfad bzw. den In-Process-Provider verwaltet.

### Wo werden die Werte gelagert?

**Private Keys**
- Werden provider-lokal im Key-Store des aktiven Providers gehalten.
- Im klassischen P-384-Pfad liegt dort ein `ECPrivateKeyParameters`-Objekt.
- Im ML-KEM-/ML-DSA-Pfad liegt dort ein provider-internes Schlüsselobjekt.
- Der Core sieht davon nur den `PrivateKeyHandle`.

**Secret Keys**
- Symmetrische Schlüssel werden provider-lokal als `byte[]` im Secret-Key-Store gehalten.
- Beispiele: AEAD-Schlüssel oder aus HKDF abgeleitete Arbeits-Schlüssel.

**Shared Secrets**
- KEM-/ECDH-Geheimnisse werden provider-lokal als `byte[]` im Shared-Secret-Store gehalten.
- Sie sind als Zwischenartefakt gedacht und sollen typischerweise zeitnah in einen `SecretKeyHandle` überführt und danach zerstört werden.

**Boundary nach Betriebsmodus**
- **Dev / `ReferenceInProcess`:** derselbe Prozess, aber weiterhin dasselbe Handle-Modell.
- **Staging/Prod / `ProductionIsolated`:** separater Worker-Prozess; über das OOP-Protokoll werden nur Handles sowie nicht geheime oder ausdrücklich erlaubte Daten transportiert.

### Lebensdauer

- Ein Handle entsteht bei **KeyGen**, **Import**, **Encapsulation/Decapsulation**, **AEAD-GenerateKey** oder **KDF-DeriveKey**.
- Ein Handle ist an die **erzeugende `IProviderSession`** gebunden.
- Handles sind **provider-gebunden**. Ein Handle eines anderen Providers wird fail-closed abgelehnt.
- Nach `Destroy(...)`, Session-Ende oder Provider-Dispose ist das Material als nicht mehr verwendbar zu behandeln.

### Zerstörung und Cleanup

- Anwendungscode soll Handles **explizit zerstören**, sobald das Material nicht mehr benötigt wird:
  - `Destroy(PrivateKeyHandle)`
  - `Destroy(SecretKeyHandle)`
  - `Destroy(SharedSecretHandle)`
- `SecretKeyHandle` und `SharedSecretHandle` werden beim Destroy aus dem Store entfernt und ihr hinterlegtes `byte[]` wird mit `CryptographicOperations.ZeroMemory(...)` überschrieben.
- Beim Dispose der Provider-Connection werden verbliebene Secret-/Shared-Secret-Arrays ebenfalls nullisiert.
- `PrivateKeyHandle` wird beim Destroy aus dem Store entfernt. Im aktuellen Stand bedeutet das vor allem **Referenzfreigabe des provider-seitigen Schlüsselobjekts**; eine bytegenaue Zeroization für alle objektbasierten Private-Key-Pfade wird nicht pauschal zugesichert.
- Temporäre Arbeitskopien von Secret-/Shared-Secret-Bytes werden nach kryptografischen Operationen nach Möglichkeit ebenfalls nullisiert.

### Export und Import

- Private-Key-Export ist **explizit** und niemals implizit.
- `ExportPrivateKey(...)` liefert rohe Secret-Bytes zurück. Der Aufrufer muss diese Bytes nach Gebrauch selbst nullisieren.
- `ExportPrivateKeySecure(...)` liefert `SecretBytes`; der enthaltene Puffer wird bei `Dispose()` automatisch überschrieben.
- Beim Import eines Private Keys werden die Eingabebytes nicht dauerhaft im Store gehalten; der Aufrufer sollte seinen eigenen Quellpuffer nach dem Import selbst nullisieren.

### Praktischer Lifecycle

```csharp
var session = /* IProviderSession */;
var kem = session.GetKem(new AlgorithmId("ECDH-P384-KEM"));
var kdf = session.GetKdf(new AlgorithmId("HKDF-SHA384"));

KemKeyPair keyPair = kem.GenerateKeyPair();
try
{
    SharedSecretHandle shared = kem.Decapsulate(keyPair.PrivateKey, ciphertext);
    try
    {
        SecretKeyHandle aeadKey = kdf.DeriveKey(shared, parameters);
        try
        {
            // aeadKey für AEAD verwenden
        }
        finally
        {
            session.Destroy(aeadKey);
        }
    }
    finally
    {
        session.Destroy(shared);
    }
}
finally
{
    session.Destroy(keyPair.PrivateKey);
}
```

Für expliziten Private-Key-Export gilt zusätzlich:

```csharp
using var exported = exportService.ExportPrivateKeySecure(privateHandle, options);
UseSecret(exported.Span);
// exported.Dispose() -> Zeroization des Export-Puffers
```

### Logging, Beobachtbarkeit und Grenzen

- Geheime Bytes dürfen nicht geloggt werden.
- Handles sind zwar transportierbare Referenzen, sollen aber ebenfalls nicht in produktiven Logs auftauchen.
- Zeroization auf dem Managed Heap bleibt **best effort**.
- Für objektbasierte Private Keys und Library-interne Zustände gibt es keine absolute Löschgarantie.
- Die starke Non-Dev-Boundary ist aktuell der **isolierte Worker-Prozess**, nicht bereits eine zertifizierte HSM- oder FIPS-Validated-Boundary.


## Sicherheitsüberlegungen

### ⚠️ Beta-Software Warnung

**WICHTIG:** Cybersuite verwendet **BouncyCastle.Cryptography 2.7.0-beta.98**, eine experimentelle Beta-Version.

**Einschränkungen:**
- ❌ **NICHT für Production-Systeme** empfohlen (Stand: März 2026)
- ⚠️ API kann sich in zukünftigen Beta-Versionen ändern
- ⚠️ Potenzielle Bugs in PQC-Implementierungen
- ⚠️ Performance-Optimierungen noch nicht vollständig

**Wann verwenden:**
- ✅ Forschung & Entwicklung
- ✅ Prototyping & Proof-of-Concepts
- ✅ Testing & Evaluation von PQC-Algorithmen
- ✅ Vorbereitung auf Post-Quantum Migration

**Production Readiness:**
- Warten Sie auf **stable Release** von BouncyCastle 2.x
- Überwachen Sie [NIST PQC Standardization Updates](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- Testen Sie gründlich mit NIST Test Vectors
- Implementieren Sie Hybrid-Ansätze (klassisch + PQC)

### Post-Quantum Sicherheit

ML-KEM und ML-DSA bieten Schutz gegen Angriffe durch Quantencomputer:

| Algorithmus | Klassische Sicherheit | Quantensicherheit | NIST-Level |
|-------------|----------------------|-------------------|------------|
| ML-KEM-512  | ~128-bit             | ~128-bit          | 1          |
| ML-KEM-768  | ~192-bit             | ~192-bit          | 3          |
| ML-KEM-1024 | ~256-bit             | ~256-bit          | 5          |
| ML-DSA-44   | ~128-bit             | ~128-bit          | 2          |
| ML-DSA-65   | ~192-bit             | ~192-bit          | 3          |
| ML-DSA-87   | ~256-bit             | ~256-bit          | 5          |

### Hybride Ansätze

Für maximale Sicherheit während der Übergangsphase empfiehlt sich die Kombination von klassischen und PQC-Algorithmen:

```csharp
// Hybrid KEM: ECDH-P384 + ML-KEM-768
var ecdhSecret = await PerformECDH(...);
var mlkemSecret = await PerformMLKEM(...);
var combinedSecret = HKDF.DeriveKey(ecdhSecret, mlkemSecret, ...);
```

### Best Practices

1. **Verwenden Sie ML-KEM-768 oder höher** für neue Deployments
2. **Validieren Sie Signaturen** immer mit der korrekten öffentlichen Schlüssellänge
3. **Rotieren Sie Schlüssel** regelmäßig
4. **Verwenden Sie Nonces** nie mehr als einmal (bei AES-GCM)
5. **Zerstören Sie Handles** nach Verwendung mit `DestroyHandleRequest`
6. **Überwachen Sie BouncyCastle-Updates** für Security Patches

---

## Performance

### Benchmarks (Beispielwerte auf Standard-Hardware)

| Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | ECDH-P384 |
|-----------|------------|------------|-------------|-----------|
| KeyGen    | ~0.5 ms    | ~0.8 ms    | ~1.2 ms     | ~2.5 ms   |
| Encap     | ~0.6 ms    | ~0.9 ms    | ~1.3 ms     | ~2.5 ms   |
| Decap     | ~0.7 ms    | ~1.0 ms    | ~1.4 ms     | ~2.5 ms   |

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | ECDSA-P384 |
|-----------|-----------|-----------|-----------|------------|
| KeyGen    | ~0.6 ms   | ~1.0 ms   | ~1.5 ms   | ~3.0 ms    |
| Sign      | ~1.2 ms   | ~2.0 ms   | ~3.0 ms   | ~3.5 ms    |
| Verify    | ~0.8 ms   | ~1.3 ms   | ~2.0 ms   | ~4.0 ms    |

### Speicherbedarf

| Algorithmus | Public Key | Private Key | Ciphertext/Signature |
|-------------|-----------|-------------|----------------------|
| ML-KEM-512  | 800 B     | 1632 B      | 768 B                |
| ML-KEM-768  | 1184 B    | 2400 B      | 1088 B               |
| ML-KEM-1024 | 1568 B    | 3168 B      | 1568 B               |
| ML-DSA-44   | 1312 B    | 2560 B      | ~2420 B              |
| ML-DSA-65   | 1952 B    | 4032 B      | ~3309 B              |
| ML-DSA-87   | 2592 B    | 4896 B      | ~4627 B              |

---

## Troubleshooting

### Häufige Fehler

#### 1. "Type not found in any namespace"
**Ursache:** BouncyCastle.Cryptography Paket fehlt oder falsche Version

**Lösung:**
```bash
# Beta-Version installieren (erforderlich für PQC)
dotnet add package BouncyCastle.Cryptography --version 2.7.0-beta.98
```

⚠️ **Wichtig:** Die Stable-Version 2.4.0 enthält **nicht** die vollständige ML-KEM/ML-DSA Unterstützung mit den neuen APIs. Verwenden Sie die Beta-Version 2.7.0+.

#### 2. "Test vectors not found"
**Ursache:** NIST Test-Vektoren nicht heruntergeladen

**Lösung:**
```powershell
cd tests\TestVectors\ML-KEM
.\download-vectors.ps1
```

#### 3. "No compatible constructor found for MLDsaSigner"
**Ursache:** Alte BouncyCastle-Version

**Lösung:** Update auf BouncyCastle 2.0+

#### 4. "Handle not found"
**Ursache:** Handle bereits zerstört oder ungültige Handle-ID

**Lösung:** Überprüfen Sie Handle-Lifecycle und vermeiden Sie doppeltes Destroy

---

## Roadmap

### Geplante Features

- [ ] **ML-DSA Test Vectors**: NIST FIPS 204 Test-Vektor-Validierung
- [ ] **HSM Integration**: Hardware Security Module Support
- [ ] **Performance Optimierungen**: Parallelisierung, Caching
- [ ] **Additional Providers**: OpenSSL, Microsoft CNG
- [ ] **Hybrid Crypto Helpers**: Built-in ECDH+ML-KEM Kombination
- [x] **Structured Logging**: ILogger<T> in allen Kernkomponenten
- [ ] **Monitoring & Telemetry**: OpenTelemetry Integration
- [ ] **NuGet Packages**: Veröffentlichung auf NuGet.org

### Version History

#### v1.0.0 (Current)
- ✅ ML-KEM (FIPS 203) Unterstützung
- ✅ ML-DSA (FIPS 204) Unterstützung
- ✅ BouncyCastle 2.0+ Kompatibilität
- ✅ NIST Test Vector Validation (ML-KEM)
- ✅ Out-of-Process Protocol
- ✅ Integration Tests

---

## Lizenz

Dieses Projekt ist proprietär und für interne Verwendung bestimmt.

Copyright © 2024-2025 Jürg Werner

---

## Kontakt & Support

**Autor:** Jürg Werner  
**Repository:** [https://github.com/JuergWerner/Cybersuite](https://github.com/JuergWerner/Cybersuite)  
**Branch:** `Änderungen-nach-stage-6-2026-03-13`

### Contributing

Pull Requests und Issues sind willkommen. Bitte beachten Sie:
1. Alle Tests müssen bestehen (`dotnet test`)
2. Code-Style: C# 13.0 (.NET 10) mit `file-scoped namespaces`
3. Dokumentation für neue Features

---

## Referenzen

### Standards & Spezifikationen
- [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST SP 800-186: Discrete Logarithm-Based Crypto](https://csrc.nist.gov/pubs/sp/800/186/final)

### Libraries & Tools
- [BouncyCastle C# API](https://github.com/bcgit/bc-csharp)
- [NIST ACVP Server](https://github.com/usnistgov/ACVP-Server)
- [xUnit.net Testing Framework](https://xunit.net/)

### Weitere Ressourcen
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/Projects/post-quantum-cryptography)
- [Post-Quantum Cryptography Alliance](https://pqca.org/)
- [IETF PQUIP Working Group](https://datatracker.ietf.org/wg/pquip/about/)

---

**Erstellt:** März 2025  
**Letzte Aktualisierung:** März 2026  
**Version:** 1.1