# Cybersuite – Best-in-Class Sicherheits- und Usability-Audit

**Audit-Typ:** tiefer Security-, Boundary-, Supply-Chain-, Operability- und Usability-Review  
**Artefakte:** beigefügte `Cybersuite.zip`, `ARCHITECTURE.md`, `README.md`  
**Audit-Datum:** 2026-03-23  
**Auditor:** ChatGPT (GPT-5.4 Pro)  
**Prüfmodus:** tiefe statische Code-, Architektur-, Doku- und Solution-Prüfung mit externem Best-in-Class-Benchmarking  
**Wichtige Einschränkung:** In der Sandbox war kein .NET SDK verfügbar. `dotnet build`, `dotnet test`, Fuzzing, Memory-Inspection, Performance-Messungen und Live-Isolationstests konnten daher nicht ausgeführt werden. Dieses Audit ist belastbar als **tiefer statischer Review**, aber **kein Ersatz für ergänzende dynamische Verifikation**.

---

## 1. Executive Summary

### Gesamturteil

**Cybersuite ist architektonisch stark, sicherheitsbewusst und für PQC-Forschung / Prototyping bemerkenswert weit. In der vorliegenden Form ist die Suite aber noch nicht best in class und nicht freigabefähig für produktive oder regulierte Sicherheitsumgebungen.**

Das Hauptproblem ist **nicht** schwache Kryptographie-Idee, sondern die Lücke zwischen **guter Architektur** und **operativer Härtung auf Best-in-Class-Niveau**:

1. Die Suite hat heute eine deutlich ehrlichere Laufzeit- und Boundary-Wahrheit als frühe Stände.
2. Die Compliance-/Trust-/Host-Kette ist substanziell besser als bei typischen Krypto-Demo-Repositories.
3. Der non-Dev-Pfad ist real out-of-process, aber **noch keine echte Sandbox-/Least-Privilege-Boundary**.
4. Release-/Provenance-/Attestation-Artefakte sind strukturiert und fail-closed eingebunden, aber **nicht kryptographisch verifiziert signiert**.
5. Secret-/Handle-Semantik ist gut gedacht, bleibt in einer Managed-Heap-/BouncyCastle-Welt aber **best effort statt best in class**.
6. Developer-Usability ist ordentlich; Operator-/Release-/Supply-Chain-Usability bleibt deutlich hinter führenden Sicherheitsplattformen zurück.

### Kurzurteil nach Einsatzszenario

| Einsatzszenario | Bewertung | Urteil |
|---|---:|---|
| R&D / PQC-Evaluation / Labor | gut | sinnvoll |
| interne Prototypen | mittel | mit Vorsicht |
| produktive Enterprise-Systeme | schwach | derzeit nein |
| regulierte / FIPS-nahe Nutzung | schwach | derzeit nein |
| best-in-class Secure Supply Chain | schwach | derzeit nein |

### Management-Satz

**Cybersuite ist heute eine gute, ehrliche und technisch interessante PQC-/Provider-Suite für Entwicklung und Forschung, aber noch keine best-in-class gehärtete Produktivplattform.**

### Scorecard (0–5)

| Bereich | Score | Kurzbegründung |
|---|---:|---|
| Architektur & Schichtentrennung | 4.5 | sauber, bewusst, konsistent |
| Compliance & Policy-Wahrheit | 4.0 | gute Truth-Chain, fail-closed Tendenz |
| Host Lifecycle & Thread-Sicherheit | 4.0 | starke Wave-2/3-Härtung |
| Secret-/Key-Handling | 3.0 | klar besser als üblich, aber Managed-Heap-best-effort |
| Boundary / Isolation | 2.0 | OOP ja, Sandbox nein |
| Supply Chain / Release Trust | 1.5 | strukturierte Bundles, aber keine signierte Kette |
| Developer-Usability | 4.0 | guter Dev-PQM-Default und Doku-Breite |
| Operator-Usability | 2.5 | Release-/Deploy-/Trust-Story nicht turnkey |
| Test- / Assurance-Posture | 3.5 | breite statische Testbasis, aber keine hier verifizierte Laufzeit |
| Production-Readiness | 1.5 | noch nicht freigabefähig |
| Regulated / FIPS Readiness | 1.0 | `ValidatedBoundary` fehlt |

---

## 2. Scope, Methode und belastbare Grundlage

### 2.1 Was geprüft wurde

Dieses Audit basiert auf:

- `ARCHITECTURE.md`
- `README.md`
- dem **gesamten entpackten Solution-Baum**
- Quellcode unter `src/`, `providers/`, `tests/`, `docs/`, `policies/`, `tools/`
- Projekt- und Packaging-Artefakten
- mitgelieferten Testvektoren unter `tests/TestVectors/ML-KEM/...`

### 2.2 Umfang der statischen Prüfung

Im geprüften Repo-Stand wurden statisch ausgewertet:

- **14** `.csproj`-Projekte
- **205** C#-Dateien (ohne `bin/obj`)
- rund **22,588** C#-Zeilen
- **250** xUnit-Tests über **29** Testdateien
  - `Cybersuite.Tests.Unit`: 203
  - `Cybersuite.Tests.Integration`: 21
  - `Cybersuite.Tests.Compliance`: 20
  - `Cybersuite.Test.Property`: 6

Zusätzlich relevant für Packaging-/Repo-Hygiene:

- **1380** mitgelieferte Dateien unter `.vs/`, `bin/` und `obj/`
- **0** CI-Workflow-Dateien unter `.github/workflows/`
- kein `global.json`
- kein `Directory.Packages.props`
- kein `NuGet.config`
- kein `Directory.Build.props`
- kein `Directory.Build.targets`

### 2.3 Methodik

Geprüft wurden insbesondere:

- Laufzeit- und Compliance-Wahrheit
- ProviderHost / Launch / Trust / Handshake
- OOP-Protokoll und Session-Bindung
- Secret-, Handle- und Nonce-Semantik
- Release-/Packaging-/Supply-Chain-Härte
- Dokumentationsgenauigkeit
- Developer- und Operator-Usability

### 2.4 Best-in-Class-Referenzrahmen

Für das Benchmarking wurden diese Referenzrahmen verwendet:

- **OWASP ASVS 5.0** als allgemeiner Applikations- und Betriebs-Referenzrahmen
- **NIST FIPS 203 / 204** für ML-KEM / ML-DSA
- **CMVP / FIPS 140-3** für die Trennung von *Algorithmusstandard* und *validierter Boundary*
- **SLSA 1.1** für Provenance / Verification / Build-Integrität
- **SPDX 3.x** als moderner SBOM-Referenzrahmen
- **TUF** und **in-toto** für Update- und Lieferketten-Integrität
- **Sigstore/Cosign** für moderne Artefakt-Signierung / Transparency / keyless flows
- **Windows AppContainer / Job Objects** als relevante Referenz für echte Prozessisolation auf Windows

**Methodischer Hinweis:** ASVS ist kein 1:1-Schema für Krypto-Provider-Frameworks. Es wurde hier selektiv auf Security-Architektur, sichere Defaults, Integrität, Supply Chain, Konfiguration, Logging, Error Handling und Operability abgebildet.

---

## 3. Architekturverständnis der vorliegenden Suite

Cybersuite ist im Kern ein **policy- und provider-gesteuertes Kryptographie-Framework** mit diesen Hauptideen:

- klar getrennte Schichten (`Runtime`, `Compliance`, `ProviderHost`, `OopProtocol`, `ProviderModel`, `Selection`, `Policy`, `Abstractions`)
- `EffectiveComplianceContext` als kanonische Laufzeitwahrheit
- `ProviderHost` als Orchestrator für Discovery, Trust, Launch, Handshake, Capability-Freeze und Lifecycle
- OOP-Protokoll mit Transcript-Hash, Channel Binding und monotonem Message Counter
- Handle-basierte Secret-Verwaltung statt roher Secret-Bytes im Kernpfad
- bewusste Trennung zwischen
  - **Dev / ReferenceInProcess / experimentell**
  - **Staging/Prod / ProductionIsolated / klassisches Stable-Subset**
- explizite Aussage, dass **ein echter `ValidatedBoundary`-/FIPS-Pfad noch fehlt**

### 3.1 Was die Suite heute wahrheitsgemäß behauptet

Der aktuelle Stand ist deutlich ehrlicher als typische Security-/Crypto-Repos:

- `Dev` ist ein **ReferenceInProcess**-Pfad mit **Development PQM** und experimentellen PQC-Capabilities.
- `Staging`/`Prod` verwenden einen **realen `ProductionIsolated`-Worker-Prozess**.
- Der non-Dev-BouncyCastle-Pfad advertisiert nur das **klassische stabile Subset**, nicht den experimentellen PQC-Katalog.
- Release-Bundle-, Provenance- und Self-Attestation-Mechanismen sind aktiv, aber bewusst **nicht** als vollständige externe Supply-Chain-/Hardware-Attestation behauptet.
- Ein echter `ValidatedBoundary`-/FIPS-Pfad ist weiterhin **nicht vorhanden**.

### 3.2 Warum diese Architektur positiv auffällt

Viele Krypto- oder PQC-Repos scheitern schon auf der Ebene von:

- Boundary-Wahrheit
- Schichtentrennung
- deterministischer Auswahl
- Secret-/Handle-Disziplin
- sauberem Host-Lifecycle

Cybersuite ist hier **überdurchschnittlich durchdacht**. Die größten Defizite liegen **nicht** in der Architekturidee, sondern in der noch unvollständigen operativen Härtung von:

- Isolation
- Supply Chain
- Release-Verifikation
- Secret-Lifecycle unter Managed-Heap-Bedingungen

---

## 4. Positive Befunde

### 4.1 Sicherheitsseitig stark

| Bereich | Positiver Befund |
|---|---|
| Clean Architecture | klare Schichtentrennung und gute Verantwortungsgrenzen |
| Build Hygiene im Projekt | `Nullable`, `TreatWarningsAsErrors`, `Deterministic`, `ContinuousIntegrationBuild` sind breit gesetzt |
| Compliance Truth Chain | `EffectiveComplianceContext` ist sinnvoll als Single Source of Truth etabliert |
| Policy-Bindung | `ProviderSessionBinding` koppelt Session, Policy-Hash und Compliance-Kontext sauber |
| Algorithm Selection | deterministisch, fail-closed, ohne versteckte globale Mutabilität |
| Replay-Schutz | Transcript-Hash, Channel Binding und monotoner Message Counter sind solide |
| Host Lifecycle | explizite Start-Transaktionen, Journal, Rollback, Stop-Gating und Retry-Verhalten |
| Multithreading | Lifecycle-Übergänge sind serialisiert, provider-lokale Operationen werden geschützt |
| Handle-Sicherheit | provider-gebundene und session-gebundene Handle-Validierung ist vorhanden |
| Transportbudgets | Größenbudgets für Control/Capability/Payload sind aktiv |
| Raw Secret Egress | non-Dev kann per Compliance Envelope raw secret egress verbieten |
| Architekturwahrheit | README/Architecture behaupten keine aktive validierte Boundary, wenn sie fehlt |

### 4.2 Usability-seitig stark

| Bereich | Positiver Befund |
|---|---|
| Dev Onboarding | `Development PQM` als shipped default ist für PQC-Lab-Arbeit sehr zugänglich |
| API-Intent | `AlgorithmId`, `ProviderId`, `SecurityStrength`, kategorisierte Services sind sauber modelliert |
| Operator Diagnostics | Start-/Failure-Journals und Snapshot-Zustände helfen Diagnose und Audits |
| Testbreite | Unit-, Integration-, Compliance- und Property-Tests sind vorhanden |
| Doku-Ehrlichkeit | README warnt explizit vor Beta/BouncyCastle und Nicht-Eignung für Produktion |

### 4.3 Wichtige bereits geschlossene Gaps

Die Waves 1–5 haben reale Sicherheitsverbesserungen geliefert:

- Wave 1: Compliance Truth Chain
- Wave 2: Host Lifecycle / Launch Context / Journaling / Multithreading-Härtung
- Wave 3: sichere Defaults, Transportbudgets, provider-gebundene Handles
- Wave 4: realer non-Dev-Workerpfad, strukturierte Provenance und Self-Attestation, klassisch-only Prod-Capability-Truth
- Wave 5 (teilweise): strukturierte Release-Bundles und `Development PQM` als shipped default

Das Audit ist deshalb **nicht** “alles schlecht”, sondern “viel richtig – aber noch nicht best in class”.

---

## 5. Summary der wichtigsten Findings

| ID | Severity | Titel |
|---|---|---|
| CS-BIC-01 | **High** | Release-, Provenance- und Attestation-Artefakte sind strukturiert, aber nicht kryptographisch signiert |
| CS-BIC-02 | **High** | `ProductionIsolated` ist Prozessabspaltung, aber keine best-in-class Sandbox/Least-Privilege-Boundary |
| CS-BIC-03 | **High** | Ein echter `ValidatedBoundary`-/FIPS-Pfad fehlt weiterhin vollständig |
| CS-BIC-04 | **High** | Staging verifiziert manifest-deklarierte Entrypoint-Integrität nicht so fail-closed wie Prod |
| CS-BIC-05 | **Medium** | `EnableNetworkAccess` ist modelliert, aber nicht OS-seitig erzwungen |
| CS-BIC-06 | **Medium** | Worker-Launch nutzt PATH-basiertes `dotnet` und vererbt die Parent-Umgebung weitgehend |
| CS-BIC-07 | **Medium** | Package-Root-/Entrypoint-Containment wird nicht hart erzwungen |
| CS-BIC-08 | **Medium** | Secret-/Key-Handling bleibt best effort; objektbasierte Private Keys werden nicht garantiert nullisiert |
| CS-BIC-09 | **Medium** | `supportsNonExportableKeys=true` ist stärker als die real technisch durchgesetzte Boundary |
| CS-BIC-10 | **Medium** | SBOM-/Release-Sidecars sind unsigniert, simplifiziert und unterhalb moderner Supply-Chain-Standards |
| CS-BIC-11 | **Medium** | BouncyCastle `2.7.0-beta.98` bleibt ein strategisches Sicherheits- und Vertrauensrisiko |
| CS-BIC-12 | **Medium** | Packaging-/Repo-Hygiene liegt unter Best-in-Class-Niveau |
| CS-BIC-13 | **Low-Medium** | Chunking/Streaming ist nur geplant; aktuelle Budgets rejecten Oversize statt echte Large-Payload-Strategie zu bieten |
| CS-BIC-14 | **Low** | README / Onboarding / Claim-Schärfe driftet an mehreren Stellen von der Solution-Wirklichkeit ab |

---

## 6. Detailbefunde

### CS-BIC-01 – Release-, Provenance- und Attestation-Artefakte sind strukturiert, aber nicht kryptographisch signiert

**Severity:** High  
**Betroffene Artefakte:**

- `src/Cybersuite.ProviderHost/Trust/StructuredReleaseBundleVerifier.cs:18-194`
- `src/Cybersuite.ProviderHost/Trust/StructuredBundleProvenanceVerifier.cs:18-107`
- `src/Cybersuite.ProviderHost/Trust/StructuredAttestationVerifier.cs:21-193`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs:98-163`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleProviderConnection.cs:779-794`

#### Befund

Die Suite hat einen **guten strukturellen Ansatz** für Release, Provenance und Attestation. Diese Artefakte werden aber faktisch nur als **Base64/JSON-Claims** transportiert und anhand von:

- Feldgleichheit
- Ablaufzeit
- Allowlist
- Hash-/Bundle-Bindung

validiert.

Es gibt **keine echte kryptographische Signaturprüfung** über diese Bundles:

- keine Signatur im Bundle-Format
- keine Trust-Root-gestützte Verifikation
- keine Sigstore/Cosign-Verifikation
- keine in-toto-Attestation
- kein TUF-Rollen-/Delegationsmodell
- keine hardware-backed Remote Attestation

Die Attestation wird im Worker sogar **self-generated** aus lokalen Feldern gebaut (`ProviderStructuredAttestationStatement`), nicht von einer unabhängigen attesting authority geliefert.

#### Warum das sicherheitsrelevant ist

Das ist der größte Best-in-Class-Gap im Bereich **Supply Chain / Lieferwahrheit**.  
Ein Angreifer, der Packaging oder Distribution beeinflussen kann, kann aktuell strukturierte, aber **unsignierte** Metadaten mitkoppeln, solange Feldkonsistenz und lokale Allowlists ausreichen.

#### Positiv daran

Die Suite ist hier immerhin **ehrlich**: Kommentare und Architekturtexte tun nicht so, als sei das bereits eine vollständige externe Supply-Chain- oder Hardware-Attestation-Lösung.

#### Best-in-Class-Zielzustand

Mindestens:

1. signierte Release-Provenance
2. signierte SBOM / Release-Manifest-Artefakte
3. verifizierbare Trust Roots / signer identities
4. bevorzugt Sigstore/Cosign oder äquivalenter Flow
5. in-toto-Attestations
6. TUF oder vergleichbare Update-/Distribution-Integrität

#### Empfehlung

- Bundles nicht nur strukturieren, sondern **signieren**
- Verifikation im Host gegen echte Roots / signers
- Release-Provenance nicht nur als Feldvergleich, sondern als **verifizierte Supply-Chain-Aussage** behandeln
- optional später Transparency Log und keyless signing ergänzen

---

### CS-BIC-02 – `ProductionIsolated` ist Prozessabspaltung, aber keine best-in-class Sandbox/Least-Privilege-Boundary

**Severity:** High  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleOutOfProcessConnection.cs:320-369`
- `providers/Cybersuite.Provider.BouncyCastle.Worker/Program.cs:13-53`

#### Befund

Der non-Dev-Pfad startet den Worker als **separaten Kindprozess** mit redirectetem `stdin/stdout/stderr`. Das ist besser als In-Process, aber **keine echte Sandbox**.

Im geprüften Code fanden sich **keine** Hinweise auf:

- AppContainer / Less-Privileged AppContainer
- Restricted Token
- Job Objects mit CPU-/Memory-/I/O-Limits
- Dateisystem-/Registry-Virtualisierung
- seccomp / namespaces / container policies
- OS-seitig erzwungene Netzwerkisolation
- Broker-/Supervisor-Härtung mit klarer Minimalberechtigung

#### Warum das sicherheitsrelevant ist

Wenn der Worker kompromittiert wird oder eine RCE-Lücke im Providerpfad hätte, läuft er **nahe an den Rechten des Elternprozesses**. Damit ist die “Boundary” operativ deutlich schwächer als eine best-in-class isolierte Provider-Grenze.

#### Einordnung

Die Architektur spricht ehrlich von `ProductionIsolated`, nicht von `ValidatedBoundary`. Das ist gut.  
Für eine **wirklich best-in-class** produktive Kryptographie-Boundary reicht Prozessabspaltung allein aber **nicht**.

#### Empfehlung

- Windows: AppContainer + Job Objects + optional Restricted Token
- Linux: seccomp / namespaces / cgroups / filesystem isolation
- Netzwerkzugriff physisch unterbinden, nicht nur logisch flaggen
- Supervisor-/Restart-/Crash-/Resource-Governance ergänzen

---

### CS-BIC-03 – Ein echter `ValidatedBoundary`-/FIPS-Pfad fehlt weiterhin vollständig

**Severity:** High  
**Betroffene Artefakte:**

- `ARCHITECTURE.md` (mehrfach, u. a. Zielbild und Akzeptanzstatus)
- `README.md` (Boundary-Truth-Status)
- `src/Cybersuite.ProviderModel/ProviderComplianceEnvelope.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs:87-97`

#### Befund

Die Suite trennt heute sauber zwischen:

- `ReferenceInProcess`
- `ProductionIsolated`
- `ValidatedBoundary`

Aber der dritte Pfad ist **architektonisch geplant, operativ nicht vorhanden**.  
Für FIPS-/regulierte Nutzung bleibt die Suite derzeit auf dem Stand:

- Fail-closed-Anforderung kann gesetzt werden
- aktiver Providerpfad, der diese Anforderung erfüllt, fehlt aber

#### Warum das sicherheitsrelevant ist

Der Unterschied zwischen:

- “wir verwenden ML-KEM / ML-DSA nach FIPS 203/204-Standard” und
- “wir laufen in einer validierten Boundary / reguliert nutzbaren Modulwelt”

ist in der Praxis fundamental.

#### Empfehlung

- separaten `ValidatedBoundary`-Providerpfad realisieren
- klar zwischen OSS-R&D-Track und validiertem / OS-/HSM-gebundenem Track trennen
- niemals implizieren, dass BouncyCastle-OSS + Worker bereits regulatorisch äquivalent sei

---

### CS-BIC-04 – Staging verifiziert manifest-deklarierte Entrypoint-Integrität nicht so fail-closed wie Prod

**Severity:** High  
**Betroffene Artefakte:**

- `src/Cybersuite.ProviderHost/Trust/DefaultProviderTrustEvaluator.cs:67-80`

#### Befund

Wenn kein explizit gepinnter erwarteter SHA-256-Wert in `ExpectedEntrypointSha256ByProvider` gesetzt ist, vergleicht der Trust Evaluator zwar die gemessene Datei mit `Manifest.EntrypointSha256Hex`, rejectet einen Mismatch aber **nur in `Prod`** explizit fail-closed.

Damit kann **Staging** mit manifestbezogener Hash-Inkonsistenz weiterlaufen, sofern kein weiteres Pinning greift.

#### Warum das sicherheitsrelevant ist

Staging ist typischerweise die Umgebung, in der Produktionsnähe, Verifikationshärte und Freigabereife demonstriert werden. Ein schwächeres Integritätsverhalten in Staging untergräbt:

- Vorproduktionsvertrauen
- Release-Validierung
- reproduzierbare Freigaben
- Security Gates

#### Empfehlung

- Manifest-Hash-Mismatch **auch in Staging fail-closed** behandeln
- non-Dev hier idealerweise vereinheitlichen
- Prod/Staging nur dort differenzieren, wo dies bewusst sicherheitlich begründet ist

---

### CS-BIC-05 – `EnableNetworkAccess` ist modelliert, aber nicht OS-seitig erzwungen

**Severity:** Medium  
**Betroffene Artefakte:**

- `src/Cybersuite.ProviderHost/ProviderHostOptions.cs:120-129`
- `src/Cybersuite.ProviderHost/Launch/ProviderLaunchContext.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleOutOfProcessConnection.cs:355-363`

#### Befund

`EnableNetworkAccess` wird sauber durch den Host-/Launch-Kontext getragen und als Environment-Variable gesetzt (`CYBERSUITE_PROVIDER_ENABLE_NETWORK_ACCESS`). Im geprüften Code fand sich aber **keine operative Durchsetzung** dieses Bits im Worker oder durch einen Sandbox-/OS-Layer.

#### Risiko

So entsteht eine Sicherheitskontrolle, die für Operatoren härter klingt, als sie tatsächlich ist. Das ist kein direkter Exploit, aber ein **truthfulness/usability/security gap**.

#### Empfehlung

- Netzwerkzugriff OS-seitig blockieren oder erlauben
- nicht nur konfigurativ modellieren, sondern technisch **erzwingen**
- falls nicht erzwungen: Dokumentation explizit als **advisory only** markieren

---

### CS-BIC-06 – Worker-Launch nutzt PATH-basiertes `dotnet` und vererbt die Parent-Umgebung weitgehend

**Severity:** Medium  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleOutOfProcessConnection.cs:320-369`

#### Befund

Wenn der Entrypoint eine `.dll` ist, startet die Suite:

```text
ProcessStartInfo("dotnet")
```

also **ohne absoluten Pfad** zum gewünschten Runtime Host. Zusätzlich wird die Environment nur ergänzt, nicht sichtbar auf ein minimales Child-Set reduziert.

#### Risiko

Das schafft mehrere Best-in-Class-Gaps:

- PATH-/Environment-Abhängigkeit
- schwerere Reproduzierbarkeit
- größere Angriffsfläche über vererbte Variablen
- schwächere operatorische Kontrollierbarkeit

#### Empfehlung

- absoluten, vertrauenswürdigen Runtime-Pfad verwenden
- Child-Environment minimal und explizit aufbauen
- nur benötigte Variablen durchreichen
- Working Directory und Entrypoint kanonisch binden

---

### CS-BIC-07 – Package-Root-/Entrypoint-Containment wird nicht hart erzwungen

**Severity:** Medium  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs:167-175`

#### Befund

`ValidatePackagePaths(...)` prüft nur:

- package root nicht leer
- entrypoint nicht leer
- entrypoint existiert

Es wird **nicht** erzwungen, dass der Entrypoint kanonisch **innerhalb des Package Roots** liegt.

#### Risiko

Für best-in-class Packaging-/Trust-Härte ist das zu schwach, weil Package und Entrypoint semantisch nur lose gekoppelt sind.

#### Empfehlung

- `Path.GetFullPath(...)` für Root und Entrypoint
- Containment hart prüfen
- optional allowlistete Dateiendungen / Dateinamen erzwingen

---

### CS-BIC-08 – Secret-/Key-Handling bleibt best effort; objektbasierte Private Keys werden nicht garantiert nullisiert

**Severity:** Medium  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleKeyMaterialStore.cs:15-17, 119-166`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleKeyImportExportService.cs:18-23, 66-93`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleCurveP384.cs`
- `providers/Cybersuite.Provider.BouncyCastle/SecretBytes.cs`

#### Befund

Die Suite ist hier **besser als viele Krypto-Repos**, aber noch nicht best in class:

- Secret- und Shared-Secret-Arrays werden beim Destroy/Dispose aktiv nullisiert.
- `SensitiveBufferLease` und `SecretBytes` helfen, Kopien zu begrenzen und beim Dispose zu löschen.
- Private Keys werden jedoch als **Objekte** im Store gehalten; beim Destroy werden sie primär **entfernt**, nicht garantiert bytegenau überschrieben.
- Der Importpfad dokumentiert offen, dass `BigInteger` / `ECPrivateKeyParameters` interne Managed-Heap-Kopien halten können.

#### Einordnung

Das ist kein unfairer Vorwurf – in Managed-Code ist perfekte Secret-Härtung schwierig. Aber gerade deshalb ist der Abstand zu **best-in-class secret handling** real.

#### Empfehlung

- private-key-sensitive Komponenten so kurzlebig wie möglich halten
- object-based private keys wo möglich reduzieren
- Export-/Importpfade weiter minimieren
- OS-/HSM-/KSP-/PKCS#11-gebundene Schlüsselobjekte als Zukunftspfad definieren
- Dokumentation noch expliziter nach “garantiert / best effort / nicht garantiert” gliedern

---

### CS-BIC-09 – `supportsNonExportableKeys=true` ist stärker als die real technisch durchgesetzte Boundary

**Severity:** Medium  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs:87-97`
- `src/Cybersuite.ProviderModel/ProviderComplianceEnvelope.cs:33-37`
- `src/Cybersuite.ProviderHost/ProviderRpcSession.cs:239-255`

#### Befund

Der non-Dev-BouncyCastle-Pfad setzt im Compliance Envelope:

- `supportsNonExportableKeys: true`
- `supportsRawSecretEgress: false`

Das ist als **logische Boundary-Aussage** nachvollziehbar. Es ist aber nicht gleichbedeutend mit einem echten OS-/HSM-gebundenen, hardware-backed oder regulatorisch validierten non-exportable key store.

#### Risiko

Für Experten ist die Semantik lesbar. Für weniger tiefe Leser kann `supportsNonExportableKeys=true` stärker klingen, als die reale technische Garantie ist.

#### Empfehlung

- Begrifflichkeit präzisieren: eher “provider-local non-export semantics” als implizite HSM-Assoziation
- echtes non-exportable Key-Object-Zielbild separat definieren
- OS-/KSP-/HSM-Backends langfristig als eigener Providerpfad

---

### CS-BIC-10 – SBOM-/Release-Sidecars sind unsigniert, simplifiziert und unterhalb moderner Supply-Chain-Standards

**Severity:** Medium  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs:109-145, 203-237`
- `src/Cybersuite.ProviderHost/Trust/StructuredReleaseBundleVerifier.cs:165-189`
- `tools/release/Generate-StructuredReleaseBundle.ps1`

#### Befund

Wave 5 ist eine gute Richtung, aber noch nicht best in class:

- `spdxVersion = "SPDX-2.3"`
- Sidecars sind unsigniert
- die erzeugte JSON-Struktur ist eher **SPDX-inspiriert** als eine robust validierte moderne SBOM-Pipeline
- Laufzeit bindet nur an Digests im Bundle, nicht an extern verifizierte Artefakte
- kein Transparenzlog / kein signer-identity-model / kein attestierter Buildflow

#### Empfehlung

- auf aktuellen SBOM-Standard heben (SPDX 3.x oder sauberer CycloneDX-Pfad)
- SBOM und Release-Manifest signieren
- Verifikation in Build- und Host-Gates integrieren
- Schema- und tool-validierte Artefakte als Pflicht machen

---

### CS-BIC-11 – BouncyCastle `2.7.0-beta.98` bleibt ein strategisches Sicherheits- und Vertrauensrisiko

**Severity:** Medium  
**Betroffene Artefakte:**

- `providers/Cybersuite.Provider.BouncyCastle/Cybersuite.Provider.BouncyCastle.csproj`
- `README.md`
- `docs/QUICKSTART.md`
- `docs/BETA-WARNING.md`

#### Befund

Die Solution pinnt weiterhin `BouncyCastle.Cryptography 2.7.0-beta.98`. README und Doku warnen ausdrücklich, dass dies **Beta-Software** und **nicht für Production** geeignet ist.

#### Einordnung

Das ist positiv ehrlich, bleibt aber ein strategischer Gap:

- höhere Unsicherheit bei Stabilität / Regressionen / Semantik
- schwächeres Sicherheits- und Auditorenvertrauen
- schwierigerer Produktions- und Change-Management-Pfad

#### Empfehlung

- R&D-/Interop-Track und Produktions-/regulierten Track sauber trennen
- OSS-Track auf stabile Linie rationalisieren, sobald sinnvoll
- FIPS-/regulierten Track separat denken, nicht über Beta-OSS “hochreden”

---

### CS-BIC-12 – Packaging-/Repo-Hygiene liegt unter Best-in-Class-Niveau

**Severity:** Medium  
**Betroffene Artefakte:**

- ausgeliefertes `Cybersuite.zip`
- `.gitignore`
- Repo-Root / Build-Controls

#### Befund

Im gelieferten Solution-ZIP liegen **1380** Dateien unter `.vs/`, `bin/` und `obj/`, obwohl `.gitignore` diese Artefakte klar ausschließt. Zusätzlich fehlen mehrere übliche Reproduzierbarkeits-/Build-Kontrollartefakte:

- `global.json`
- `Directory.Packages.props`
- `NuGet.config`
- `Directory.Build.props`
- `Directory.Build.targets`
- CI-Workflows

#### Warum das relevant ist

Für ein Kryptographie-/Provider-Framework ist Packaging-Hygiene kein kosmetisches Thema. Sie beeinflusst:

- Reproduzierbarkeit
- Auditierbarkeit
- Build-Wahrheit
- Supply-Chain-Risiko
- Operator-Vertrauen

#### Empfehlung

1. **clean source release** statt Arbeitsverzeichnis-ZIP
2. `.vs/`, `bin/`, `obj/` nie ausliefern
3. `global.json` pinnen
4. zentrale Paketversionierung erwägen
5. CI-Workflows und reproduzierbare Build-Pipeline im Repo verankern
6. signierte Release-Artefakte und maschinenlesbare Release-Metadaten ergänzen

---

### CS-BIC-13 – Chunking/Streaming ist nur geplant; aktuelle Budgets rejecten Oversize statt echte Large-Payload-Strategie zu bieten

**Severity:** Low-Medium  
**Betroffene Artefakte:**

- `src/Cybersuite.ProviderHost/Launch/OopTransportBudget.cs:11-83`
- `src/Cybersuite.ProviderHost/OopTransportBudgetGuard.cs:8-52`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleWorkerProtocol.cs:45-79`

#### Befund

Wave 3 hat sinnvolle Transportbudgets eingebaut. Das schützt vor unkontrolliert großen Nachrichten und ist sicherheitlich korrekt. Gleichzeitig bleibt der aktuelle OOP-Transport:

- length-prefixed
- JSON-basiert
- inline-message-orientiert

und rejectet Oversize-Payloads mit Chunking-Hinweis, statt echte Streaming-/Chunking-Protokolle zu liefern.

#### Wirkung

Sicherheitlich ist das vernünftig, operativ/usability-seitig aber eine klare Grenze für große Artefakte, künftige Provider und robuste Produktionsszenarien.

#### Empfehlung

- echtes Streaming-/Chunking-Design implementieren
- kontrollierte große Payloads ermöglichen, ohne Budgets aufzuweichen
- Protokoll- und API-Usability für große Artefakte verbessern

---

### CS-BIC-14 – README / Onboarding / Claim-Schärfe driftet an mehreren Stellen von der Solution-Wirklichkeit ab

**Severity:** Low  
**Betroffene Artefakte:**

- `README.md`
- `docs/QUICKSTART.md`
- Repo-Struktur insgesamt

#### Konkret beobachtet

1. README nennt **“.NET 8 SDK oder höher”**, obwohl die Projekte auf **`net10.0`** zielen.
2. README beschreibt die Suite teils als “modernes, hochsicheres Framework”, während an anderer Stelle korrekt vor Beta-/Nicht-Production-Einsatz gewarnt wird.
3. Die Test-Vektor-Beschreibung klingt an manchen Stellen stärker als der reale Testmodus.
4. Release-/Boundary-Wahrheit ist inzwischen deutlich besser, aber die Doku ist noch nicht überall maximal knapp und operatorisch eindeutig.

#### Warum das wichtig ist

Für einen kryptographischen Stack sind präzise, driftfreie Aussagen Teil der **operativen Vertrauenswürdigkeit**.

#### Empfehlung

- README automatisiert gegen Solution und Build-Parameter prüfen
- “docs as code”-Checks einführen
- Dev-/Staging-/Prod-/ValidatedBoundary-Matrix im README noch knapper machen
- leistungsstarke, aber nicht produktionsreife Dev-Defaults fortlaufend unmissverständlich markieren

---

## 7. Usability Audit

### 7.1 Was gut funktioniert

#### Developer Experience

- `Development PQM` als shipped default ist für lokale PQC-Experimente pragmatisch und sofort nutzbar.
- Die Policy-/Provider-Modellierung ist verständlich.
- `PolicyDefaults.CreateDevelopmentPqm()` und die Sample Policies schaffen einen klaren Einstieg.
- Die Architektur trennt Dev und non-Dev inzwischen klarer als viele ähnliche Projekte.
- `QUICKSTART.md` und README decken zentrale Flows gut ab.

#### Operator Experience

- `ProviderHost` hat eine saubere Zustandsmaschine.
- Journals, Failure-States und Snapshots helfen Diagnose und Audit.
- Release-/Provenance-/Attestation-Status werden mitgeführt.
- non-Dev hat heute deutlich mehr “fail-closed by construction” als typische R&D-Repos.

### 7.2 Wo Usability aktuell Sicherheitsrisiken verstärkt

#### 1. Dev-Default ist angenehm, aber für flüchtige Leser missverständlich

`Development PQM` als shipped default ist für Entwickler gut. Für weniger gründliche Leser kann es trotzdem so wirken, als sei der PQC-/BC-Dev-Pfad der normale Standardpfad – obwohl README und Architektur zurecht sagen, dass dies **kein Produktivpfad** ist.

#### 2. Operator-Usability ist noch nicht “secure turnkey”

Es gibt noch keinen klar abgeschlossenen Standard-Workflow für:

- signierte Releases
- verifizierte SBOMs
- vertrauenswürdige Roots / signer identities
- reproduzierbare Builds
- OS-spezifisch gehärtete Provider-Isolation

#### 3. Packaging-Hygiene schadet Vertrauen

Wenn ein Repo-ZIP `.vs/`, `bin/` und `obj/` enthält, sinkt das Vertrauen eines Operators oder Auditors sofort – selbst wenn der Code an vielen Stellen durchdacht ist.

#### 4. Build-/Runtime-Anforderungen sind nicht vollkommen konsistent dokumentiert

Ein Sicherheitsframework sollte in README, Quickstart, Projekttargets und Release-Doku praktisch **widerspruchsfrei** sein. Diese Schwelle ist noch nicht ganz erreicht.

---

## 8. Best-in-Class Gap Analysis

| Bereich | Aktueller Zustand | Best-in-Class-Zustand | Gap |
|---|---|---|---|
| Boundary / Isolation | separater Worker-Prozess | echte Sandbox + least privilege + Ressourcenlimits | hoch |
| Release / Provenance | strukturierte, aber unsignierte Bundles | signierte, verifizierte Provenance + verifizierbare Roots | hoch |
| Update-/Distribution-Trust | kein TUF-/Update-Framework | TUF-/Rollen-/Delegationsmodell oder äquivalent | hoch |
| SBOM | simplifizierter unsignierter Sidecar-Ansatz | validierter aktueller SBOM-Standard + Signatur + Verifikation | mittel bis hoch |
| FIPS-/ValidatedBoundary | ehrliche Nicht-Behauptung | echter validierter Provider-/Boundary-Pfad | strategisch hoch |
| Runtime Integrity | Prod streng, Staging schwächer | non-Dev konsistent fail-closed | mittel |
| Worker Hardening | stdio child process | AppContainer / Job Objects / seccomp / broker / limits | hoch |
| Secret Handling | gute best-effort Hygiene | OS-/HSM-/KSP-gebundene non-exportable key objects | hoch |
| Reproducibility | fehlende Root-Build-Controls | pinned SDK + central package control + CI + reproducible builds | mittel |
| Assurance Tests | gute statische Breite, vektorbasierte Integration | deterministische KATs + differential tests + fuzzing + runtime verification | mittel |
| Docs / Operator Clarity | brauchbar, aber driftend | automatisiert konsistente Security- und Ops-Doku | niedrig bis mittel |

---

## 9. Einordnung gegen die externen Referenzrahmen

### 9.1 OWASP ASVS 5.0

Cybersuite ist in mehreren ASVS-nahen Themen für ein internes Crypto-Framework überdurchschnittlich:

- fail-closed Tendenz
- gute Trennung von Policy / Runtime / Provider Host
- bewusste Integritäts- und Trust-Pfade
- kontrollierte Fehlerflächen
- Logging-/Audit-Disziplin

Der größte ASVS-nahe Gap liegt bei:

- Security hardening of runtime isolation
- verifizierbarer Lieferkette
- reproduzierbarer, auditierbarer Release-Kette

### 9.2 NIST FIPS 203 / 204

Algorithmisch bewegt sich die Suite in die richtige Richtung. Aber:

- FIPS 203 / 204 bedeuten **Algorithmusstandard**, nicht automatisch **produktive oder validierte Modulrealität**.
- Die Suite ist erfreulich ehrlich genug, diese Gleichsetzung nicht zu behaupten.

### 9.3 CMVP / FIPS 140-3

Best in class im FIPS-nahen Sinn heißt nicht nur “wir implementieren approved algorithms”, sondern:

- validierte Module
- definierte Security Boundary
- passende Betriebsmodi
- harte Boundary- und Lifecycle-Garantien

Die Suite ist hier klar noch **nicht** angekommen.

### 9.4 SLSA / Sigstore / in-toto / TUF

Hier liegt die größte Supply-Chain-Lücke:

- Metadaten sind strukturiert
- aber nicht verifiziert signiert
- nicht in eine robuste Update-/Distribution-Story eingebettet
- und nicht transparent geloggt

### 9.5 Moderne Secret-/Key-Modelle

Cybersuite ist klar stärker als typische Byte[]-API-Krypto-Beispiele. Aber best in class im Umgang mit Secret Keys heißt langfristig:

- OS-/HSM-gebundene Schlüsselobjekte
- echte non-exportability
- garantierte Boundary-Semantik
- minimale Secret Egress-Pfade

Die Suite ist heute eher auf dem Stand “**gute Software-Disziplin**” als “**vollwertige HSM-/KSP-/validated-boundary semantics**”.

---

## 10. Priorisierte Roadmap

### 10.1 P0 – 0 bis 30 Tage

1. **README / QUICKSTART / Doku konsolidieren**
   - `.NET 10` statt `.NET 8`
   - Boundary-Matrix klar und kompakt
   - Testvektor-Aussagen präzisieren

2. **Staging fail-closed angleichen**
   - manifest-deklarierte Entrypoint-Hash-Mismatches auch in Staging blockieren

3. **Entrypoint/Package-Containment erzwingen**
   - kanonische Pfade
   - Entrypoint muss innerhalb des Package Roots liegen

4. **Packaging-Hygiene bereinigen**
   - `.vs/`, `bin/`, `obj/` nicht ausliefern
   - clean source release und getrennte binary releases

5. **Fehleroberflächen non-Dev härten**
   - Worker-/Host-Fehlermeldungen stärker sanitizen

### 10.2 P1 – 30 bis 90 Tage

1. **Child process hardening**
   - Windows: AppContainer / Job Objects / Restricted Token
   - Linux: seccomp / namespaces / cgroups / filesystem isolation

2. **Launch trust hardening**
   - absoluten Runtime-Pfad
   - minimales Child-Environment
   - Netzwerkzugriff technisch erzwingen

3. **Signierte Release-/Provenance-Artefakte**
   - Signaturformat + Trust Root
   - Verifikation im Host

4. **SBOM-Reife erhöhen**
   - aktueller SBOM-Standard
   - Signatur und Verifikation

### 10.3 P2 – 90 bis 180 Tage

1. **SLSA-/in-toto-/Sigstore-kompatible Provenance**
2. **TUF-artige oder äquivalente Update-/Distribution-Sicherheit**
3. **Deterministische PQC-KAT-Hooks**
4. **Differential testing gegen zweite Implementierung**
5. **echter `ValidatedBoundary`-/FIPS-Strategiepfad**
6. **OS-/KSP-/HSM-basierte non-exportable Key Objects**

---

## 11. Release- und Freigabeempfehlung

| Frage | Antwort |
|---|---|
| Ist die Suite für PQC-Forschung und internes Prototyping geeignet? | **Ja** |
| Ist sie aktuell best in class? | **Nein** |
| Ist sie derzeit produktiv freigabefähig? | **Nein** |
| Ist sie für regulierte / FIPS-nahe Nutzung geeignet? | **Nein** |
| Ist die Architektur vielversprechend? | **Ja, deutlich** |
| Ist der dokumentierte Sicherheitswille glaubwürdig? | **Ja** |
| Ist die operative Härtung schon auf gleichem Niveau? | **Noch nicht** |

### Ampel

- **Dev / Lab / Forschung:** Gelb-Grün
- **interne Vorproduktion:** Gelb
- **Production:** Rot
- **regulierte / FIPS-nahe Produktion:** Rot

---

## 12. Konkrete Schlussformel

Cybersuite ist **kein oberflächlich zusammengebauter PQC-Demo-Code**, sondern eine ernsthaft entworfene Suite mit vielen richtigen Architekturentscheidungen:

- kanonische Compliance-Wahrheit
- replay-sicheres OOP-Protokoll
- gute Multithreading-Invarianten
- Secret-/Handle-Disziplin
- deutlich ehrlichere Boundary-Dokumentation

Gerade deshalb fällt auf, wo der entscheidende Gap zu “best in class” noch liegt:

> **Die Suite ist architektonisch weiter als ihre operative Supply-Chain- und Boundary-Härtung.**

Solange

- Release-/Provenance-/Attestation-Artefakte nicht kryptographisch verifiziert,
- Worker nicht wirklich sandboxed,
- non-Dev-Integrität nicht konsistent fail-closed,
- und Packaging/Release/Docs nicht vollständig reproduzierbar und präzise sind,

ist das System **noch nicht** auf Best-in-Class-Niveau.

**Belastbares Urteil:**  
Cybersuite ist **stark im Design, mittel in der derzeitigen operativen Sicherheitsreife und schwach in der Best-in-Class-Produktionshärtung**.

---

## Appendix A – Konkrete Code-Evidenzen

### Architektur- und Wahrheitspfad

- `src/Cybersuite.Abstractions/EffectiveComplianceContext.cs`
- `src/Cybersuite.ProviderModel/ProviderComplianceEnvelope.cs`
- `src/Cybersuite.Runtime/RuntimeBindingFactory.cs`
- `src/Cybersuite.ProviderHost/ProviderSessionBinding.cs`

### Host / Lifecycle / MT-Sicherheit

- `src/Cybersuite.ProviderHost/ProviderHost.cs`
- `src/Cybersuite.ProviderHost/LiveProviderSessionState.cs`
- `src/Cybersuite.ProviderHost/ProviderRpcSession.cs`
- `src/Cybersuite.ProviderHost/SessionHandleTracker.cs`

### OOP / Replay / Binding

- `src/Cybersuite.OopProtocol/Handshake/HandshakeTranscript.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleProviderConnection.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleWorkerProtocol.cs`

### Release / Trust / Supply Chain

- `src/Cybersuite.ProviderHost/Trust/StructuredBundleProvenanceVerifier.cs`
- `src/Cybersuite.ProviderHost/Trust/StructuredReleaseBundleVerifier.cs`
- `src/Cybersuite.ProviderHost/Trust/StructuredAttestationVerifier.cs`
- `src/Cybersuite.ProviderHost/Trust/DefaultProviderTrustEvaluator.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleManifestFactory.cs`
- `tools/release/Generate-StructuredReleaseBundle.ps1`

### Worker / Isolation

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleOutOfProcessConnection.cs`
- `providers/Cybersuite.Provider.BouncyCastle.Worker/Program.cs`

### Secret-/Key-Handling

- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleKeyMaterialStore.cs`
- `providers/Cybersuite.Provider.BouncyCastle/BouncyCastleKeyImportExportService.cs`
- `providers/Cybersuite.Provider.BouncyCastle/SecretBytes.cs`

### Test-Assurance

- `tests/Cybersuite.Tests.Integration/MlKemTestVectorTests.cs`
- `tests/TestVectors/ML-KEM/...`
- `tests/Cybersuite.Tests.Compliance/...`
- `tests/Cybersuite.Tests.Unit/...`

### Doku / Onboarding

- `ARCHITECTURE.md`
- `README.md`
- `docs/QUICKSTART.md`
- `docs/INDEX.md`

---

## Appendix B – Relevante externe Referenzen

1. **OWASP ASVS 5.0**  
   - https://owasp.org/www-project-application-security-verification-standard/  
   - https://owasp.org/www-project-application-security-verification-standard/migrated_content

2. **NIST FIPS 203 / 204 / PQC**  
   - https://csrc.nist.gov/pubs/fips/203/final  
   - https://csrc.nist.gov/pubs/fips/204/final  
   - https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards

3. **CMVP / FIPS 140-3**  
   - https://csrc.nist.gov/projects/cryptographic-module-validation-program

4. **SLSA 1.1**  
   - https://slsa.dev/spec/v1.1/  
   - https://slsa.dev/blog/2025/04/slsa-v1.1  
   - https://slsa.dev/spec/v1.1/levels

5. **SPDX**  
   - https://spdx.dev/learn/overview/  
   - https://spdx.github.io/spdx-spec/v3.0.1/

6. **TUF / in-toto / Sigstore**  
   - https://theupdateframework.io/docs/overview/  
   - https://in-toto.io/docs/overview/  
   - https://docs.sigstore.dev/about/overview/

7. **Windows AppContainer / Job Objects**  
   - https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation  
   - https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects

8. **.NET X509 revocation guidance**  
   - https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509revocationmode?view=net-10.0

9. **Bouncy Castle OSS / FIPS Linien**  
   - https://www.nuget.org/packages/BouncyCastle.Cryptography/  
   - https://www.bouncycastle.org/documentation/documentation-c/  
   - https://www.bouncycastle.org/documentation/specification_interoperability/  
   - https://www.bouncycastle.org/about/bouncy-castle-fips-faq/

---

## Appendix C – Kompakte Management-Zusammenfassung

**Was ist gut?**
- starke Architektur
- gute Compliance- und Session-Wahrheit
- reale Host-/Lifecycle-/Thread-Sicherheitsarbeit
- saubere Handle-/Secret-Disziplin für einen Managed-Code-Stack
- ehrliche Boundary-Dokumentation

**Was fehlt zum Best-in-Class-Status?**
- echte Sandbox-Isolation
- signierte, verifizierte Supply Chain
- echter `ValidatedBoundary`-/FIPS-Pfad
- reproduzierbare Release-/Build-Kette
- noch härtere Secret-/Key-Semantik

**Freigabe heute?**
- Forschung / Prototyping: **ja**
- Produktion: **nein**
- reguliert / FIPS-nah: **nein**
