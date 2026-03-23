# Cybersuite – Architekturstatus nach Sprint/Wave 5

**Doc-Version:** AC-2.5.0  
**Stand:** 2026-03-22  
**Status:** Zielarchitektur AC-2.0.0 bleibt gültig; Wave 1 bis Wave 4 bleiben aktiv; **Wave 5 ist gestartet** mit strukturierter Release-/Packaging-Härtung und **Development PQM als shipped default**.  
**Sprache:** de-CH  
**Supersedes:** AC-2.4.4 Wave-4-Full-Repo-Compile-Corrected-With-ProviderHost-Test-Fixups  
**Input-Basis:** `security-usability-audit-v3.md`, `ARCHITECTURE_CANON.md`, AC-2.4.4 Wave-4-Full-Repo-Compile-Corrected-With-ProviderHost-Test-Fixups, `TestVectors.zip`

---

## 0. Zweck

Dieses Dokument ist die Reinjection-Baseline nach dem **Start von Sprint/Wave 5**.
Es hält fest,
welche Teile der Zielarchitektur nach Wave 4 unverändert aktiv bleiben,
welche Wave-5-Härtungen jetzt **bereits im Codepfad** aktiv sind
und welche Teile der Packaging-/Supply-Chain-Zielarchitektur weiterhin **noch nicht**
als vollständig umgesetzt behauptet werden.

Wave 5 adressiert primär den bisher offenen Audit-/Gap-Block:

- **CS-AUD-04 / Packaging, Release und Lieferwahrheit**
- eine klarere Trennung zwischen **Dev-Default** und **Produktiv-Wahrheit**
- eine reduzierte Footgun-Gefahr für lokale PQC-Entwicklung durch einen expliziten **Development-PQM-Default**

Die Architekturbehauptung nach dem Start von Wave 5 lautet damit präziser:

> Cybersuite bleibt produktiv ehrlich: non-Dev nutzt weiterhin den realen `ProductionIsolated`-
> Worker-Pfad für BouncyCastle, während ein echter `ValidatedBoundary`-/FIPS-Pfad weiterhin fehlt.
> Neu ist, dass non-Dev zusätzlich ein **strukturiertes Release-Bundle** verlangt,
> welches Repository, Release-Kanal, Signer-Fingerprint sowie Release-Manifest-/SBOM-Digests fail-closed bindet.
> Gleichzeitig ist der **mitgelieferte Standardpfad** für lokale Entwicklung jetzt bewusst
> **Development PQM**: Dev, ReferenceInProcess, experimentelle PQC-Capabilities und BouncyCastle-Pinning.

---

## 1. Aktiver Zielzustand nach Wave 5

### 1.1 Was jetzt aktiv ist

1. **Die Wave-1-Compliance-Truth-Chain bleibt unverändert aktiv.**  
   `EffectiveComplianceContext`, `ProviderComplianceEnvelope`, gemeinsame Selection-/Session-
   Admission und FIPS→Validated-Boundary-Fail-Closed bleiben die kanonische Laufzeitwahrheit.

2. **Die Wave-2-Host-Lifecycle-State-Machine bleibt unverändert aktiv.**  
   Host-Lifecycle, Start-Transaktionen, Failure Journal, kombinierte Deadlines,
   echter `ProviderLaunchContext` sowie die serialisierten Lifecycle-Übergänge bleiben aktiv.

3. **Die Wave-3-Safe-Defaults und Multithreading-Invarianten bleiben vollständig aktiv.**  
   Strikte non-Dev-Policy-Verifikation, Transportbudgets, provider-gebundene Handle-Dereferenzierung,
   provider-lokale Serialisierung und cleanup-orientierter Stop bleiben aktiv.

4. **Die Wave-4-Boundary-Wahrheit bleibt unverändert aktiv.**  
   Der BouncyCastle-Produktivpfad ist weiterhin ein echter `ProductionIsolated`-Worker-Pfad,
   non-Dev wertet strukturierte Provenance vor dem Launch und strukturierte Self-Attestation
   im Handshake fail-closed aus.

5. **Wave 5 macht Release-/Lieferwahrheit ausserhalb `Dev` operativ relevant.**  
   Ein non-Dev-Package ohne **strukturiertes Release-Bundle** wird jetzt vor dem Launch
   fail-closed zurückgewiesen.

6. **Das strukturierte Release-Bundle bindet jetzt sechs operative Wahrheiten.**  
   Es bindet:
   - `ProviderId`
   - `EntrypointSha256Hex`
   - `SecurityClass`
   - `BoundaryClass`
   - `ReleaseVersion`
   - `ReleaseChannel`
   - `SourceRepository`
   - `ReleaseManifestSha256Hex`
   - `SbomSha256Hex`
   - `SignerFingerprint`
   - `IssuedAtUtc` und optional `ExpiresAtUtc`

7. **Repository-, Channel- und Signer-Allowlists sind jetzt im Host-Trust-Pfad anschliessbar.**  
   `ProviderHostOptions` kann ausserhalb `Dev` jetzt explizit erlaubte
   Repository-URIs, Release-Kanäle und Release-Signer-Fingerprints fail-closed erzwingen.

8. **Release-Manifest- und SBOM-Digests sind jetzt non-Dev-relevant.**  
   Ausserhalb `Dev` werden ungültige oder fehlende SHA-256-Digest-Claims
   für Release-Manifest und SBOM fail-closed rejectet, wenn die entsprechenden Gates aktiv sind.

9. **Release-Status wird jetzt im Registry-Snapshot persistiert.**  
   `ProviderRecord` trägt jetzt zusätzlich `ReleaseStatus`, Repository-URI,
   Release-Kanal, Signer-Fingerprint sowie die beiden Digest-Felder.

10. **Der BouncyCastle-Produktivpfad emittiert jetzt strukturierte Release-Bundles.**  
    `BouncyCastleManifestFactory.CreateProductionIsolatedPackage(...)` erzeugt
    neben Provenance auch ein strukturiertes Release-Bundle und schreibt best-effort
    seitliche Artefakte unter `release/provider-release.manifest.json` und `release/provider-release.sbom.json`.

11. **Der shipped default für lokale Entwicklung ist jetzt bewusst `Development PQM`.**  
    Die mitgelieferten Defaults zeigen jetzt explizit auf einen lokalen PQC-Entwicklungsmodus:
    - `PolicyDefaults.CreateDevelopmentPqm()`
    - `PolicyDefaults.CreateDevelopmentPqmJsonTemplate()`
    - `policies/sample.policy.json`
    - `policies/development-pqm.policy.json`
    - `BouncyCastleManifestFactory.CreateDevelopmentPqmPackage(...)`

12. **Development PQM ist bewusst kein Produktiv-Claim.**  
    Der neue Default bedeutet nicht, dass non-Dev oder Prod jetzt standardmässig PQC
    über den Worker-Pfad advertisiert. Der shipped default betrifft explizit die lokale
    Entwicklung und den Referenzpfad.

13. **Die Wave-4-Capability-Wahrheit bleibt ehrlich bestehen.**  
    Dev/Reference kann experimentelle PQC-Algorithmen advertisieren;
    `ProductionIsolated`/BouncyCastle bleibt weiterhin klassisch-only,
    bis ein späterer echter produktiver PQC-/Validated-Boundary-Pfad existiert.

### 1.2 Was bewusst noch nicht als aktiv behauptet wird

Diese Punkte bleiben weiterhin **spätere Teile von Wave 5** oder **Future**:

- echte externe CI-/Release-Signaturkette mit vollständigem SLSA-/TUF-/in-toto-Anspruch
- kryptographische Verifikation eines extern signierten SBOM-/Release-Artefaktsets
- vollständige Deployment-/Distribution-Policy über mehrere Feeds/Artefaktquellen
- echter `ValidatedBoundary`-/FIPS-Providerpfad
- hardware-backed Remote-Attestation
- OOP-Sandboxing / Restart-Supervision / Broker-Härtung auf Service-Niveau
- echte Chunking-/Streaming-Transportschicht

### 1.3 Wirkung der neuen Defaults

Die shipped defaults sind jetzt absichtlich **entwicklerfreundlich**, ohne die Produktivwahrheit zu verwässern:

1. Lokale Entwicklung landet standardmässig im **Development-PQM-Modus**.
2. Der Dev-Default bleibt klar als **ReferenceInProcess** + **experimentell** markiert.
3. Produktive bzw. non-Dev-Pfade bleiben weiterhin **nicht** PQC-default.
4. Produktive Packages tragen jetzt zusätzlich Release-Wahrheit, statt nur Provenance und Attestation.

---

## 2. Architekturentscheidungen, die Wave 5 konkret realisiert

## [PKG-BIC-001] Strukturierte Source-Release-Bundle-Enforcement

**Realisierung:** aktiv im Codepfad, aber noch nicht als vollständige externe Supply-Chain-Lösung behauptet.

### Implementierte Form

- `src/Cybersuite.ProviderModel/ProviderReleaseStatus.cs`
- `src/Cybersuite.ProviderHost/Trust/IProviderReleaseVerifier.cs`
- `src/Cybersuite.ProviderHost/Trust/ProviderReleaseVerificationResult.cs`
- `src/Cybersuite.ProviderHost/Trust/ProviderStructuredReleaseBundle.cs`
- `src/Cybersuite.ProviderHost/Trust/StructuredReleaseBundleVerifier.cs`
- `src/Cybersuite.ProviderHost/Trust/DefaultProviderTrustEvaluator.cs`
- `src/Cybersuite.ProviderHost/ProviderHostOptions.cs`
- `src/Cybersuite.ProviderHost/ProviderHost.cs`
- `src/Cybersuite.ProviderHost/ProviderRegistrySnapshot.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleWorkerProtocol.cs`
- `tools/release/Generate-StructuredReleaseBundle.ps1`
- `tools/release/README.md`

### Aktive Regeln

1. ausserhalb `Dev` ist ein strukturiertes Release-Bundle standardmässig erforderlich
2. das Bundle muss `ProviderId`, Entrypoint-Hash, SecurityClass und BoundaryClass korrekt binden
3. `ReleaseVersion` muss zum Manifest passen
4. Repository-, Channel- und Signer-Allowlists können fail-closed erzwungen werden
5. Release-Manifest- und SBOM-Digests müssen non-Dev als gültige SHA-256-Claims vorliegen, wenn die Gates aktiv sind
6. abgelaufene Bundles werden rejectet
7. das Release-Resultat wird im `ProviderRecord` persistiert

### Sicherheitswirkung

- Packaging-/Release-Wahrheit ist nicht mehr bloss dokumentiert, sondern host-seitig operationalisiert
- non-Dev kann kein release-loses oder release-inkonsistentes Package mehr stillschweigend starten
- Snapshot, Audit und Failure Journal sehen jetzt auch den Release-Status

### Wichtige Klarstellung

Wave 5 behauptet **noch nicht**, dass damit bereits eine vollständige,
extern verifizierte Supply-Chain erreicht sei. Aktiv ist eine strukturierte,
fail-closed **Bundle- und Metadata-Bindung**, nicht eine komplette SLSA-/TUF-/Sigstore-Lösung.

## [DEV-BIC-001] Development PQM als shipped default

**Realisierung:** aktiv.

### Implementierte Form

- `src/Cybersuite.Policy/PolicyDefaults.cs`
- `policies/sample.policy.json`
- `policies/development-pqm.policy.json`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs`
- `README.md`
- `docs/QUICKSTART.md`

### Aktive Regeln

1. der mitgelieferte Beispielpfad zeigt standardmässig auf **`Development` + `Pqc`**
2. der Default pinnt `ML-KEM-768` und `ML-DSA-65` auf `BouncyCastle`
3. der mitgelieferte Dev-Package-Helper erzeugt einen **ReferenceInProcess**-Pfad
4. der Dev-Default trägt bewusst **keine** Produktiv- oder FIPS-Behauptung

### Sicherheits- und Usability-Wirkung

- lokale PQC-Entwicklung startet ohne zusätzliche Policy-Bastelei in einem konsistenten Modus
- der Default ist ehrlicher als ein pseudo-produktiver PQC-Default
- Dev und Prod werden klarer getrennt, statt implizit vermischt

## [PKG-BIC-002] Release-Sidecars als best-effort Artefakte

**Realisierung:** aktiv als Packaging-Hilfe.

### Implementierte Form

`BouncyCastleManifestFactory.CreateProductionIsolatedPackage(...)` erzeugt zusätzlich:

- `release/provider-release.manifest.json`
- `release/provider-release.sbom.json`

### Bedeutung

Diese Sidecars dienen der Liefer- und Prüfbarkeit im Repo-/Paketkontext.
Die Laufzeit bindet aber nicht an die Dateien selbst,
sondern an die im Release-Bundle transportierten Digests.

---

## 3. Aktive Multithreading- und Sicherheitsinvarianten nach Wave 5

## 3.1 Host- und Session-Sicherheit bleiben unverändert aktiv

Wave 2 bis Wave 4 bleiben vollständig aktiv:

- Lifecycle-Mutationen bleiben serialisiert
- `OpenSession(...)` bleibt gegen Lifecycle-Änderungen synchronisiert
- pro Live-Provider bleiben Operationen serialisiert
- `StopAsync` markiert Sessions zuerst als `stopping`
- neue Calls failen danach geschlossen

## 3.2 Die neue Release-Verifikation ist rein host-seitig und thread-safe

Die Release-Prüfung läuft im bestehenden Trust-Pfad, also vor dem Launch.
Sie erweitert keine Parallelität im Worker-Kanal und ändert nicht die bisherigen
provider-lokalen Serialisierungsinvarianten.

## 3.3 Cross-Provider-Parallelität bleibt erhalten

Die zusätzlichen Release-Gates sind per-Provider/Package-Prüfungen.
Sie ändern nicht die aktive Architekturentscheidung,
dass mehrere verschiedene Provider parallel betrieben werden dürfen.

---

## 4. Was die Suite jetzt ehrlich behauptet

1. Der shipped default für lokale Entwicklung ist jetzt **Development PQM**.
2. Dieser Default ist ausdrücklich ein **Dev-/Reference-/Experimentalpfad**.
3. Der aktive non-Dev-BouncyCastle-Pfad bleibt ein **realer `ProductionIsolated`-Worker-Pfad**.
4. non-Dev verlangt jetzt zusätzlich ein **strukturiertes Release-Bundle**.
5. Dieses Bundle bindet Repository, Release-Kanal, Signer-Fingerprint und Manifest-/SBOM-Digests aktiv in den Trust-Pfad ein.
6. Ein vollständiger externer Release-/SBOM-/SLSA-/TUF-Anspruch wird weiterhin **nicht** als aktiv behauptet.
7. Ein echter `ValidatedBoundary`-/FIPS-Pfad existiert weiterhin **noch nicht**.

---

## 5. Code-Artefakte von Wave 5

### Neue Kern-Artefakte

- `src/Cybersuite.ProviderModel/ProviderReleaseStatus.cs`
- `src/Cybersuite.ProviderHost/Trust/IProviderReleaseVerifier.cs`
- `src/Cybersuite.ProviderHost/Trust/ProviderReleaseVerificationResult.cs`
- `src/Cybersuite.ProviderHost/Trust/ProviderStructuredReleaseBundle.cs`
- `src/Cybersuite.ProviderHost/Trust/StructuredReleaseBundleVerifier.cs`
- `src/Cybersuite.Policy/PolicyDefaults.cs`
- `tests/Cybersuite.Tests.Unit/Policy/PolicyWave5Tests.cs`
- `tests/Cybersuite.Tests.Unit/ProviderHost/ProviderHostWave5Tests.cs`
- `tools/release/Generate-StructuredReleaseBundle.ps1`
- `tools/release/README.md`
- `policies/development-pqm.policy.json`

### Geänderte Kern-Artefakte

- `ARCHITECTURE.md`
- `CYBERSUITE_STATE.yaml`
- `README.md`
- `docs/QUICKSTART.md`
- `policies/sample.policy.json`
- `src/Cybersuite.ProviderHost/ProviderHostOptions.cs`
- `src/Cybersuite.ProviderHost/ProviderPackage.cs`
- `src/Cybersuite.ProviderHost/ProviderHost.cs`
- `src/Cybersuite.ProviderHost/ProviderRegistrySnapshot.cs`
- `src/Cybersuite.ProviderHost/Trust/IProviderTrustEvaluator.cs`
- `src/Cybersuite.ProviderHost/Trust/DefaultProviderTrustEvaluator.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleWorkerProtocol.cs`

---

## 6. Akzeptanzstatus nach Wave 5

| Gate | Status | Bemerkung |
|---|---|---|
| AG-CMP-001 | erreicht im Codepfad | Wave-1-Truth-Chain bleibt aktiv |
| AG-CMP-002 | erreicht im Codepfad | Selection und Session nutzen denselben Wahrheitsraum |
| AG-BND-001 | erreicht im Codepfad | non-Dev kann Referenzpfade weiterhin nicht stillschweigend öffnen |
| AG-BND-002 | erreicht im Codepfad | realer `ProductionIsolated`-BC-Worker bleibt aktiv |
| AG-HOST-001 | erreicht im Codepfad | Host-Rollback und Journaling bleiben aktiv |
| AG-HOST-002 | erreicht im Codepfad | Retry und cleanup-orientierter Stop bleiben aktiv |
| AG-LAU-001 | erreicht im Codepfad | realer Launch-Context bleibt aktiv |
| AG-MT-001 | erreicht im Codepfad | provider-lokale Serialisierung bleibt aktiv |
| AG-POL-001 | erreicht im Codepfad | Wave-3-Policy-Defaults bleiben aktiv |
| AG-TRN-001 | erreicht im Codepfad | Wave-3-Transportbudgets bleiben aktiv |
| AG-HND-001 | erreicht im Codepfad | Wave-3-Handle-Semantik bleibt aktiv |
| AG-TRU-001 | erreicht im Codepfad | strukturierte Provenance bleibt non-Dev Pflicht |
| AG-ATT-001 | erreicht im Codepfad | strukturierte Self-Attestation bleibt aktiv |
| AG-CAP-001 | erreicht im Codepfad | produktiver BC-Worker bleibt klassisch-only |
| AG-PKG-001 | **teilweise erreicht im Codepfad** | strukturiertes Release-Bundle + Allowlists + Digest-Gates sind aktiv; externe CI-/Sigstore-/TUF-Kette bleibt offen |
| AG-DEV-001 | erreicht im Codepfad | shipped sample policy und Helper defaulten auf Development PQM |
| AG-FIPS-001 | offen | echter `ValidatedBoundary`-/FIPS-Pfad bleibt Future |

---

## 7. Nächster Block innerhalb von Wave 5

Der nächste sinnvolle Implementierungsblock innerhalb Wave 5 bleibt:

> **Wave 5b – Release Pipeline Truth and External Verification**

mit diesen Kernaufgaben:

- stärkere Hash-/Signer-Bindung an echte Release-Artefakte ausserhalb des Package-Manifests
- Vorbereitung einer echten externen Release-/SBOM-Signaturkette
- stärkere Distribution-/Feed-Wahrheit
- vorbereitende Trennung für einen späteren echten `ValidatedBoundary`-Provider

---

## 8. Schlussformel

Nach dem Start von Wave 5 ist Cybersuite weiterhin **nicht** reguliert-ready
und noch nicht als vollständig gehärtete Produktivsuite zu behaupten.

Aber die gelieferte Architektur ist in zwei Punkten klarer und besser:

> non-Dev besitzt jetzt neben Provenance und Attestation auch eine erste echte
> **Release-/Packaging-Wahrheit** im Host-Trust-Pfad,
> und die mitgelieferten Defaults sind jetzt explizit auf **Development PQM** ausgerichtet,
> ohne den produktiven Boundary-Truth zu verwässern.
