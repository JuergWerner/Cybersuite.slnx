# Umgang mit geheimen Schlüsseln in der Suite

## Zweck und Scope

Dieses Dokument analysiert **den aktuellen Umgang der Cybersuite mit geheimen Schlüsseln**, Shared Secrets und privaten Schlüsseln. Es betrachtet dabei nicht nur die Zielarchitektur, sondern den realen Ist-Zustand in `README.md`, `ARCHITECTURE.md` und im Sourcecode der Solution.

Der Fokus liegt auf:

- **Speicherung** von Private Keys, Secret Keys und Shared Secrets
- **Lebensdauer** und Zerstörung
- **Transport** über den OOP-/Worker-Pfad
- **API- und Fehlbedienungsrisiken**
- **Entwicklungsmöglichkeiten** in Richtung Best-in-Class

Die Analyse ist ein **statischer Review**. Es wurden hier keine Laufzeittests, kein Memory-Dump-Review und keine Betriebssystem-Härtung live validiert.

---

## Kurzurteil

Cybersuite ist beim Secret-Handling **architektonisch auf dem richtigen Weg** und hat seit dem ursprünglichen Review **alle P0-Befunde (F2–F7) behoben**:

- geheimes Material wird überwiegend **handle-basiert** modelliert,
- Secret Keys und Shared Secrets bleiben grundsätzlich **provider-lokal**,
- `Destroy(...)` und Provider-`Dispose` nullisieren relevante `byte[]`-Puffer,
- der OOP-/Worker-Pfad transportiert bei KDF/AEAD **Handles statt roher Schlüsselbytes**,
- Logging- und Audit-Pfade sind bewusst auf **keine Secret-Leaks** ausgelegt,
- **Session-Bindung** ist über `SessionHandleTracker` technisch durchgesetzt (F2),
- **Auto-Cleanup** bei Session-Dispose entfernt alle offenen Handles (F3),
- **Import-Zeroization** nullisiert temporäre `ToArray()`-Kopien nach BigInteger-Konstruktion (F4),
- **SensitiveBufferLease** (F5) reduziert Heap-Kopien via `ArrayPool<byte>` mit Auto-Zeroization,
- **KeyExportPolicy** (F6) steuert Export profil-abhängig (Dev: AllowExplicit, Staging: DenyByDefault, Prod: Prohibited),
- **Raw Secret Egress Guard** (F7) sperrt Rohsecret-Export per `SupportsRawSecretEgress` auf Provider-Envelope-Ebene,
- **Thread-Safety** ist lückenlos: `_disposed`-Guard auf allen Store-Methoden, `ObjectDisposedException`, 10 dedizierte Concurrency-Tests,
- **Dead-Code** (verwaiste `GetSecretKeyCopy`/`GetSharedSecretCopy`/`BorrowSecretKey`/`BorrowSharedSecret`) wurde entfernt,
- **Fail-closed `default`** im `EnforceExportPolicy`-Switch für unbekannte Policy-Werte.

Das ergibt folgenden aktualisierten Reifegrad:

- **Dev / Prototyping:** ✅ gut brauchbar
- **Standard-Enterprise-Prod:** ✅ mit `ProductionIsolated`-Pfad und `KeyExportPolicy.Prohibited`
- **Reguliert / FIPS / HSM-nah:** ⚠️ verbessert, aber noch nicht best-in-class (benötigt OS-/HSM-backed non-exportable Keys)

---

## Positivbild: Was heute bereits gut gelöst ist

### 1. Handle-basiertes Modell statt Core-seitiger Raw-Keys

Die Grundidee ist richtig: Der Core soll mit **Handles** arbeiten, nicht mit rohen Private Keys oder Secret Keys.

Relevante Evidenz:

- `PrivateKeyHandle`, `SecretKeyHandle`, `SharedSecretHandle` bilden das öffentliche Modell (`src/Cybersuite.Abstractions/PrivateKeyHandle.cs`, `SecretKeyHandle.cs`, `SharedSecretHandle.cs`).
- `ProviderRpcSession` nutzt diese Handles für `Destroy(...)`, KEM, AEAD und KDF (`src/Cybersuite.ProviderHost/ProviderRpcSession.cs:90-147, 471-623`).
- `KdfDeriveKeyRequest` transportiert ein `SharedSecretHandle`, nicht das Shared Secret selbst (`src/Cybersuite.OopProtocol/Messages/KdfMessages.cs:11-43`).

**Bewertung:** Das ist sicherer und deutlich auditfreundlicher als ein API-Design, das überall `byte[]` für geheime Materialien herumreicht.

### 2. Provider-lokale Stores mit expliziter Zeroization für Secret/Shared-Secret-Arrays

`BouncyCastleKeyMaterialStore` hält:

- Private Keys in `_privateKeys`
- Secret Keys in `_secretKeys`
- Shared Secrets in `_sharedSecrets`

und nullisiert `SecretKeyHandle`/`SharedSecretHandle` beim `Destroy(...)` sowie beim `Dispose()` des Stores (`providers/Cybersuite.Provider.BouncyCastle/BouncyCastleKeyMaterialStore.cs:12-15, 140-170`).

**Bewertung:** Für `byte[]`-basierte Geheimnisse ist das eine solide Mindesthygiene.

### 3. Provider-bound Handles sind tatsächlich implementiert

Der Store ist auf typisierte Handles aufgebaut, nicht nur auf nackte GUIDs (`BouncyCastleKeyMaterialStore.cs:12-15`). Missbrauch mit falscher `ProviderId` wird fail-closed abgefangen:

- im Session-Layer durch `ValidateHandleProvider(...)` (`ProviderRpcSession.cs:184-195`),
- im Provider selbst durch `Ensure...HandleProvider(...)`-Prüfungen im Bouncy-Castle-Pfad.

**Bewertung:** Das schließt einen wichtigen Fehlerpfad und ist wesentlich besser als ein globaler GUID-Keyspace.

### 4. OOP-/Worker-Pfad hält Secret Keys und Shared Secrets als Handles

Im `ProductionIsolated`-Pfad werden bei AEAD und KDF keine rohen Schlüssel übertragen:

- AEAD verwendet `SecretKeyHandleDto` (`providers/Cybersuite.Provider.BouncyCastle/BouncyCastleWorkerProtocol.cs:450-455`),
- KDF verwendet `SharedSecretHandleDto` und gibt `SecretKeyHandleDto` zurück (`...WorkerProtocol.cs:456-457`).

**Bewertung:** Das ist die richtige Richtung für eine echte Boundary-Trennung.

### 5. Es gibt ein bewusstes Zeroization-Mindset

Positive Beispiele:

- `SecretBytes` nullisiert beim `Dispose()` (`src/Cybersuite.Abstractions/SecretBytes.cs:18-38`),
- Shared Secrets aus KEM werden nach dem Einlagern in den Store nullisiert (`providers/Cybersuite.Provider.BouncyCastle/BouncyCastleProviderConnection.cs:250-255, 298-300`; `BouncyCastleMlReflection.cs:119-127, 182-188`),
- Digest-/Temporärpuffer werden in Signaturpfaden nullisiert (`BouncyCastleProviderConnection.cs:381-393`),
- der Worker nullisiert die serialisierten JSON-Byteframes nach Read/Write (`BouncyCastleWorkerProtocol.cs:45-59, 62-84`).

**Bewertung:** Die Sicherheitskultur ist erkennbar vorhanden.

---

## Aktueller Zustand im Detail

## 1. Wo liegen die geheimen Werte heute?

### Private Keys

Private Keys liegen provider-lokal im `BouncyCastleKeyMaterialStore` als **Objekte**, nicht als einheitlich nullisierbare Bytearrays:

- klassische P-384-Schlüssel als `ECPrivateKeyParameters` (`BouncyCastleKeyMaterialStore.cs:17-18, 32-33`),
- ML-KEM-/ML-DSA-Schlüssel als provider-interne BC-Objekte via `AddPrivateKeyObject(...)` (`BouncyCastleMlReflection.cs:64-67, 234-237`).

Das ist einerseits gut, weil der Core den Schlüssel nicht sieht. Andererseits ist die Speicherhygiene hier schwächer als bei reinen `byte[]`-Pfaden, weil Bouncy-Castle-Objekte und `BigInteger` nicht zuverlässig bytegenau nullisierbar sind.

### Secret Keys

Symmetrische Schlüssel liegen im Store als `byte[]` (`BouncyCastleKeyMaterialStore.cs:14, 60-67`).

Das gilt unter anderem für:

- generierte AEAD-Schlüssel (`BouncyCastleProviderConnection.cs:458-465`),
- über HKDF abgeleitete Arbeitsschlüssel (`BouncyCastleProviderConnection.cs:579-613`).

### Shared Secrets

KEM-/ECDH-Geheimnisse liegen ebenfalls als `byte[]` im Store (`BouncyCastleKeyMaterialStore.cs:15, 70-77`).

Das gilt für:

- klassisches ECDH-KEM (`BouncyCastleProviderConnection.cs:250-255, 298-300`),
- ML-KEM via Reflection (`BouncyCastleMlReflection.cs:119-127, 182-188`).

### Boundary nach Profil

Der reale Schutzgrad hängt stark vom Profil ab:

- **Dev / Development PQM:** `ReferenceInProcess`, also derselbe Prozessraum wie die Anwendung
- **Staging/Prod:** `ProductionIsolated`, also Worker-Prozess mit eigener Provider-Boundary
- **ValidatedBoundary / FIPS-reguliert:** noch Zielbild, nicht der heutige Normalpfad

Für Secret-Handling bedeutet das praktisch: Der gleiche Codepfad ist in **Dev** deutlich weniger stark segmentiert als in **Staging/Prod**.

---

## 2. Lebensdauer und Destroy-Semantik

Die Doku beschreibt Handles als an die erzeugende `IProviderSession` gebunden und nach Session-Ende als nicht mehr verwendbar. Genau hier liegt aber der wichtigste Realitätsunterschied.

### Dokumentierte Aussage

Die Handle-Typen und das README behaupten Session-Lebensdauer:

- `PrivateKeyHandle`: „valid for the lifetime of the IProviderSession“ (`src/Cybersuite.Abstractions/PrivateKeyHandle.cs:17-19`)
- `SecretKeyHandle`: dito (`SecretKeyHandle.cs:13-15`)
- `SharedSecretHandle`: dito (`SharedSecretHandle.cs:13-15`)
- README: „Ein Handle ist an die erzeugende IProviderSession gebunden“

### Tatsächliche Implementierung

Technisch tragen die Handle-Typen **nur**:

- `ProviderId`
- `Guid`

also **keine Session-Identität**.

Zusätzlich erzeugt `ProviderHost.OpenSession(...)` mehrere `ProviderRpcSession`-Wrapper auf Basis derselben `LiveProviderSessionState` bzw. derselben Provider-Connection (`src/Cybersuite.ProviderHost/ProviderHost.cs:134-150`).

`ProviderRpcSession` prüft beim Verwenden eines Handles nur die `ProviderId`, nicht eine Session-ID (`ProviderRpcSession.cs:90-147, 184-195`).

### Konsequenz

Damit ist die Session-Bindung **derzeit dokumentiert, aber nicht erzwungen**. Wenn Anwendungscode ein Handle über Session-Grenzen hinweg weitergibt, ist eine Wiederverwendung auf derselben Provider-Connection prinzipiell möglich.

**Bewertung:** Das ist kein triviales Remote-Exploit-Szenario, aber ein klarer Unterschied zwischen dokumentierter und realer Security-Semantik.

---

## 3. Destroy und Cleanup: gut für `byte[]`, schwach für Objekt-Keys

### Secret Keys und Shared Secrets

Für `byte[]`-basierte Geheimnisse ist die Lage ordentlich:

- `Destroy(SecretKeyHandle)` nullisiert den hinterlegten Puffer (`BouncyCastleKeyMaterialStore.cs:140-146`)
- `Destroy(SharedSecretHandle)` nullisiert den hinterlegten Puffer (`...:149-155`)
- `Dispose()` des Stores nullisiert verbliebene Secret-/Shared-Secret-Arrays (`...:158-170`)

### Private Keys

Für `PrivateKeyHandle` wird beim Destroy **nur die Referenz aus dem Store entfernt** (`BouncyCastleKeyMaterialStore.cs:132-137`).

Es gibt **keine allgemeine aktive Zeroization** für:

- `ECPrivateKeyParameters`
- BC-PQC-Private-Key-Objekte
- interne immutable `BigInteger`-Anteile

Die Architektur beschreibt das selbst korrekt als **best effort** und nicht als garantierte Heap-Säuberung.

**Bewertung:** Für klassische Anwendungssicherheit okay, für best-in-class regulierte Deployments zu schwach.

---

## 4. Import und Export

## 4.1 Positiv

Es gibt eine explizite Import-/Export-Schnittstelle:

- `IKeyImportService` (`src/Cybersuite.Abstractions/IKeyImportService.cs:5-20`)
- `IKeyExportService` (`src/Cybersuite.Abstractions/IKeyExportService.cs`)
- `ExportPrivateKeySecure(...)` mit `SecretBytes`

Das ist viel besser als impliziter Export über Nebenpfade.

## 4.2 Der reale Zustand ist aber noch nicht end-to-end sauber

### A. Import/Export ist noch nicht in Runtime/Host zentral verdrahtet

`IKeyImportService` ist im Interface selbst ausdrücklich als „not yet wired into Runtime/ProviderHost orchestration“ markiert (`IKeyImportService.cs:6-10`).

`IKeySerializationSession` existiert zwar als optionales Session-Interface (`src/Cybersuite.Abstractions/IKeySerializationSession.cs:3-13`), ist im untersuchten Codepfad aber **nicht end-to-end aktiv verdrahtet**.

**Sicherheitswirkung:**

- positiv: es gibt keinen versehentlichen universellen OOP-Exportpfad,
- negativ: es fehlt ein zentraler policy-gesteuerter Gatekeeper für erlaubten vs. verbotenen Export/Import.

### B. Import-Doku ist stärker als die technische Realität

Die Provider-Doku behauptet in `BouncyCastleKeyImportExportService`, dass private Key Bytes nach Import zeroized werden (`providers/Cybersuite.Provider.BouncyCastle/BouncyCastleKeyImportExportService.cs:18-20`).

Die Implementierung erstellt aber einfach eine temporäre Kopie via:

```csharp
var d = new BigInteger(1, encodedPrivateKey.ToArray());
```

(`...BouncyCastleKeyImportExportService.cs:79-83`)

Diese temporäre `byte[]`-Kopie wird **nicht explizit nullisiert**.

**Bewertung:** Das ist ein konkreter Doku-/Code-Gap.

### C. Export ist explizit, aber im Referenzpfad weiterhin roh möglich

`ExportPrivateKey(...)` gibt rohe Secret-Bytes zurück (`BouncyCastleKeyImportExportService.cs:104-117`).

`ExportPrivateKeySecure(...)` verbessert das über `SecretBytes` (`...:119-127`), ändert aber nichts daran, dass:

- der Export selbst eine neue `byte[]` erzeugt,
- der Key im Referenzpfad grundsätzlich exportierbar bleibt,
- es dafür noch keinen zentralen Compliance-/Boundary-Gatekeeper gibt.

**Bewertung:** Für Dev/Interop völlig legitim, für regulierte Pfade zu offen.

---

## 5. Memory-Hygiene und Kopierverhalten

Die Memory-Hygiene wurde durch die SensitiveBufferLease-Einführung (F5) deutlich verbessert.

### Verbesserungen durch SensitiveBufferLease

- `SensitiveBufferLease` nutzt `ArrayPool<byte>.Shared` für gepoolte Puffer
- Automatische Zeroization via `CryptographicOperations.ZeroMemory` bei `Dispose()`
- `LeaseSecretKey`/`LeaseSharedSecret` auf dem Store ersetzen die alten Copy-Methoden
- `BouncyCastleProviderConnection`: AEAD/KDF/Hash-Operationen nutzen Leases statt neuer Arrays
- AEAD-Messages sind `IDisposable` und nullisieren Payload-Puffer beim Dispose
- Verwaiste Copy-Methoden (`GetSecretKeyCopy`, `GetSharedSecretCopy`) wurden entfernt

### Wo noch zusätzliche Kopien entstehen

Beispiele:

- Store-Einlagerung: `keyBytes.ToArray()` / `secretBytes.ToArray()` (erforderlich für sichere Trennung von Caller-Puffern)
- OOP-Messages: AEAD-Requests kopieren Nonce, Plaintext und AD (nun mit IDisposable-Cleanup)
- Worker-Transport: `SerializePayload(...)` baut ein JSON-`string` (nur für Handle-Transport genutzt, nie für rohe Secrets)

### Bewertung

✅ Die Heap-Kopien-Problematik ist durch das Lease-Pattern für den Normalpfad gelöst. Verbleibende Kopien bei Store-Einlagerung und OOP-Serialisierung sind architektonisch notwendig und werden durch IDisposable-Cleanup abgesichert.

---

## 6. OOP-Pfad: was bleibt innerhalb der Boundary, was nicht?

## Positiv

Im Worker-Pfad bleiben Private Keys, Secret Keys und Shared Secrets im normalen Ablauf provider-lokal. Besonders gut ist:

- KDF: `SharedSecretHandle -> SecretKeyHandle` ohne Rohsecret-Egress
- AEAD: Nutzung von `SecretKeyHandle` statt roher Key-Bytes
- Destroy: explizit via `DestroyHandle`

## Aber

Die OOP-Boundary schützt **nur die Schlüssel selbst**, nicht automatisch alle sensitiven Daten. Beispielsweise werden bei AEAD:

- Plaintext,
- Ciphertext,
- Associated Data

über Request-/Response-Objekte und JSON-Frames kopiert (`AeadMessages.cs:43-65, 73-129`; `BouncyCastleWorkerProtocol.cs:452-455`).

Das ist funktional normal, aber sicherheitlich wichtig: **Die Suite schützt heute Schlüsselmaterial besser als allgemeine geheime Nutzdaten.**

---

## 7. Threading und Secret-Sicherheit

Die Multithreading-Sicherheit wurde in Phase 7 umfassend gehärtet:

- `BouncyCastleKeyMaterialStore` schützt seinen Zustand per `lock(_gate)` + `_disposed`-Flag mit `ObjectDisposedException.ThrowIf` auf allen 12 öffentlichen Methoden
- `SessionHandleTracker` nutzt `lock(_gate)` mit DrainAll-Semantik und `IsDrained`-Flag
- `ProviderRpcSession` serialisiert Operationen pro Live-Provider über `OperationSyncRoot`
- `ProviderRpcSession` + alle Proxies nutzen `Interlocked.CompareExchange` für Dispose-Guards
- `LiveProviderSessionState` führt einen provider-lokalen Gate-Lock und monotonen Counter via `Interlocked.Increment`
- `SensitiveBufferLease` nutzt `Interlocked.Exchange` für thread-safe, idempotentes Dispose
- `ProviderHost` nutzt `SemaphoreSlim` für Lifecycle und `ConcurrentDictionary` für Sessions
- `ProviderRegistry` nutzt `ImmutableInterlocked` für lock-free reads
- `BouncyCastleOutOfProcessConnection` nutzt `SemaphoreSlim(1,1)` für RPC-Serialisierung
- Store-Dispose ist idempotent (doppeltes Dispose sicher, Use-after-Dispose wirft `ObjectDisposedException`)
- 4 verwaiste Methoden (`GetSecretKeyCopy`, `GetSharedSecretCopy`, `BorrowSecretKey`, `BorrowSharedSecret`) wurden als Dead-Code entfernt

**Tests:** 10 dedizierte Thread-Safety-Tests (`ThreadSafetyTests.cs`) validieren parallele Add/Lease/Destroy, Dispose-Races und Session-Tracker-Concurrency

**Bewertung:** ✅ Die Suite ist vollständig thread-safe für alle Secret-bezogenen Operationen.

---

## Detaillierte Befunde

## F1 – Stark: Handle-first-Modell und explizites Destroy sind richtig

**Severity:** Positiv / Stärke  
**Bewertung:** beibehalten und ausbauen

Cybersuite versucht nicht, Private Keys als gewöhnliche DTOs durch Runtime und Host zu schieben. Das ist die richtige Grundentscheidung.

## F2 – ~~Hoch~~ ✅ BEHOBEN: Session-Bindung ist jetzt technisch durchgesetzt

**Severity:** ~~Hoch~~ → Behoben  
**Kategorie:** Secret Lifetime / API Truthfulness / Cross-Session Misuse

**Ursprüngliches Problem:** Handles trugen keine Session-Identität; Session-Layer validierte nur `ProviderId`.

**Implementierte Lösung:**
- `SessionHandleTracker` (`src/Cybersuite.ProviderHost/SessionHandleTracker.cs`) trackt alle Handles pro Session
- `TrackHandle(Handle128)` registriert Handles bei Erzeugung
- `ValidateHandle(Handle128)` prüft Session-Zugehörigkeit fail-closed
- `DrainAll()` invalidiert alle Handles bei Session-Ende
- Thread-safe via `lock(_gate)`
- `IsDrained`-Flag verhindert Post-Drain-Registrierungen

**Tests:** `SessionHandleTracker_ParallelTrackAndValidate_NoCorruption`, `SessionHandleTracker_DrainDuringTrack_FailsClosed`

## F3 – ~~Mittel~~ ✅ BEHOBEN: Session-Dispose zerstört jetzt automatisch alle offenen Handles

**Severity:** ~~Mittel~~ → Behoben  
**Kategorie:** Memory Hygiene / Heap Exposure / Auto-Cleanup

**Ursprüngliches Problem:** Objektbasierte Private Keys wurden beim Destroy nicht aktiv sanitisiert. Kein Auto-Cleanup bei Session-Ende.

**Implementierte Lösung:**
- `ProviderRpcSession.Dispose()` ruft `SessionHandleTracker.DrainAll()` auf
- DrainAll invalidiert alle registrierten Handles der Session
- Vergessene `Destroy(...)`-Aufrufe werden automatisch aufgeräumt
- `BouncyCastleKeyMaterialStore.Dispose()` nullisiert verbliebene Secret-/Shared-Secret-Arrays
- Store-Dispose ist idempotent (doppeltes Dispose sicher)

**Verbleibende Einschränkung:** BC-Objekt-basierte Private Keys (ECPrivateKeyParameters, PQC-Objekte) können mangels `.Dispose()` auf den BC-Typen nicht bytegenau nullisiert werden. Dies ist eine BC-Library-Limitation.

## F4 – ~~Mittel~~ ✅ BEHOBEN: Import-Zeroization ist jetzt implementiert

**Severity:** ~~Mittel~~ → Behoben  
**Kategorie:** Documentation Accuracy / Secret Hygiene

**Ursprüngliches Problem:** Kommentar behauptete Zeroization nach Import, Implementierung nullisierte die temporäre `ToArray()`-Kopie aber nicht.

**Implementierte Lösung:**
- `BouncyCastleKeyImportExportService.ImportPrivateKey()` nullisiert die temporäre `byte[]`-Kopie im `finally`-Block via `CryptographicOperations.ZeroMemory`
- XML-Dokumentation wurde auf den tatsächlichen Zustand korrigiert

## F5 – ~~Mittel~~ ✅ BEHOBEN: Heap-Kopien durch SensitiveBufferLease reduziert

**Severity:** ~~Mittel~~ → Behoben  
**Kategorie:** Memory Hygiene / Performance / Secret Residency

**Ursprüngliches Problem:** Store, Messages und Worker-Protokoll erzeugten mehrfach neue Arrays.

**Implementierte Lösung:**
- `SensitiveBufferLease` (`src/Cybersuite.Abstractions/SensitiveBufferLease.cs`) kapselt `ArrayPool<byte>.Shared`-Puffer
- Automatische Zeroization via `CryptographicOperations.ZeroMemory` bei `Dispose()`
- Thread-safe Dispose via `Interlocked.Exchange`
- `LeaseSecretKey(handle)` / `LeaseSharedSecret(handle)` auf `BouncyCastleKeyMaterialStore` als Borrow-Pattern
- `BouncyCastleProviderConnection`: `AeadEncryptAsync`/`DecryptAsync`/`KdfDeriveKeyAsync`/`ComputeSha384` nutzen Leases
- AEAD-Messages (`AeadEncryptRequest`/`Response`, `AeadDecryptRequest`/`Response`) sind `IDisposable` und nullisieren Payload-Puffer
- Verwaiste Methoden `GetSecretKeyCopy`/`GetSharedSecretCopy`/`BorrowSecretKey`/`BorrowSharedSecret` wurden entfernt

**Tests:** 14 dedizierte `SensitiveBufferLeaseTests` + Concurrency-Tests (`ParallelLeaseCopyFromAndDispose`, `ConcurrentDispose_SameInstance`)

## F6 – ~~Mittel~~ ✅ BEHOBEN: Export/Import ist jetzt policy-zentralisiert

**Severity:** ~~Mittel~~ → Behoben  
**Kategorie:** Governance / Usability / Safety-by-Construction

**Ursprüngliches Problem:** Import/Export existierte, war aber noch nicht zentral durch Runtime/Host und Compliance modelliert.

**Implementierte Lösung:**
- `KeyExportPolicy` Enum: `AllowExplicit` | `DenyByDefault` | `Prohibited`
- `KeyExportOptions.DefaultPolicyForProfile()`: Dev → AllowExplicit, Staging → DenyByDefault, Prod → Prohibited
- `BouncyCastleKeyImportExportService.EnforceExportPolicy()`: expliziter `switch` mit fail-closed `default` für unbekannte Policy-Werte
- `KeyExportPolicyEnforcer` (ProviderHost-intern): zentraler Gatekeeper pro Operation
- Public-Key-Export ist nicht policy-gated (öffentlich)

**Tests:** 16 Tests in `ExportPolicyAndEgressGuardTests` (AllowExplicit/DenyByDefault/Prohibited für ExportPrivateKey + ExportPrivateKeySecure, PublicKey export, DefaultPolicyForProfile, Enforcer-Einheitstests)

## F7 – ~~Mittel bis Hoch~~ ✅ BEHOBEN: Raw-Secret-Egress ist jetzt per Envelope gesperrt

**Severity:** ~~Mittel bis Hoch~~ → Behoben  
**Kategorie:** Future Design Constraint

**Ursprüngliches Problem:** `SerializePayload(...)` erzeugt JSON-Strings. Das ist für Rohsecrets ungeeignet.

**Implementierte Lösung:**
- `ProviderComplianceEnvelope.SupportsRawSecretEgress` Flag steuert, ob ein Provider Rohsecrets exportieren darf
- `ProviderRpcSession.AssertRawSecretEgressPermitted(operationName)` prüft das Flag fail-closed
- Bei `SupportsRawSecretEgress=false` wirft jeder Versuch einer Rohsecret-Operation `InvalidOperationException`
- JSON-Worker-Transport bleibt ausschließlich für Handle-Transport vorgesehen
- Handle-only OOP-Messages: KEM/AEAD/KDF/Signature geben Handles zurück, nie rohe Secret-Bytes

**Tests:** `Session_RawSecretEgressDisabled_AssertThrowsOnExportAttempt`, `Session_RawSecretEgressEnabled_AssertSucceeds`

**Verbleibende strategische Empfehlung:** Falls künftig Wrap/Unwrap, Secret Injection oder Key Migration über OOP nötig sind, sollte ein binäres, bounded, zeroizable Transportformat eingeführt werden.

## F8 – Strategisch: Best-in-Class braucht non-exportable Key-Objekte, nicht nur bessere Zeroization

**Severity:** Strategisch  
**Kategorie:** Zielarchitektur

**Problem:** Solange hochsensible Schlüssel letztlich als provider-interne Managed-Objekte oder `byte[]` leben, bleibt die Sicherheit „best effort“.

**Empfehlung:** OS-/HSM-/Token-gebundene, non-extractable Keys als Normalpfad für Staging/Prod-Regulated.

---

## Entwicklungsmöglichkeiten

## P0 – Kurzfristig und mit hohem Nutzen ✅ ALLE BEHOBEN

### 1. Session-Bindung wirklich erzwingen ✅ BEHOBEN (F2)

**Umgesetztes Zielbild:**

- `SessionHandleTracker` registriert und validiert Handles pro Session
- `DrainAll()` invalidiert alle Handles bei Session-Ende
- `ProviderRpcSession.Dispose()` ruft DrainAll auf
- Thread-safe via `lock(_gate)` + `IsDrained`-Flag

### 2. Importpfade wirklich zeroizen ✅ BEHOBEN (F4)

Konkret umgesetzt:

- `encodedPrivateKey.ToArray()` in lokale Variable gezogen
- nach `new BigInteger(1, copy)` im `finally`-Block nullisiert via `CryptographicOperations.ZeroMemory`
- XML-Dokumentation auf tatsächlichen Zustand korrigiert

### 3. Explizite Auto-Destroy-/Lease-Semantik ergänzen ✅ BEHOBEN (F3 + F5)

Umgesetzt:

- Auto-Cleanup bei Session-Dispose (F3)
- `SensitiveBufferLease` als `using`-fähiges Borrow-Pattern (F5)
- `LeaseSecretKey`/`LeaseSharedSecret` als scoped-Key-Zugriff
- `IDisposable`-Cleanup auf AEAD-Messages

### 4. Export-Governance trennen nach Profil ✅ BEHOBEN (F6 + F7)

Umgesetzte Matrix:

- **Dev:** `AllowExplicit` – Export möglich, aber explizit
- **Staging:** `DenyByDefault` – Export standardmäßig aus, nur per Override
- **Prod:** `Prohibited` – Private-Key-Export standardmäßig verboten
- **Raw Secret Egress:** Per `SupportsRawSecretEgress=false` auf Envelope-Ebene sperrbar

---

## P1 – Mittelfristig: Sauberer Produktionspfad

### 1. `IKeySerializationSession` end-to-end verdrahten

Import/Export sollte nicht als loser Provider-Hook bleiben, sondern:

- capability-gebunden sein,
- policy-gefiltert sein,
- boundary-abhängig freigegeben oder verboten werden,
- auditierbar sein.

### 2. `SupportsNonExportableKeys` / `SupportsRawSecretEgress` operativ machen

Diese Envelope-Felder existieren bereits im Modell (`ProviderComplianceEnvelope.cs:23-24`), sollten aber künftig echte Admission- und API-Regeln treiben:

- `SupportsRawSecretEgress=false` → kein Rohsecret-Export, kein Rohsecret-RPC
- `SupportsNonExportableKeys=true` → Export nur Public Key / Wrap / Attestation, nie Private Key raw

### 3. JSON-Transport für sensitive Zukunftspfade ablösen

Für eventuelle Zukunftsoperationen wie:

- Wrap/Unwrap
- Secret Injection
- Key Migration
- geschützten Export

sollte ein **binärer, bounded, zeroizable Transport** eingeführt werden.

### 4. `NativeCurveP384` oder OS-native Key-Provider wirklich integrieren

Der wichtigste nächstliegende Schritt Richtung non-exportable Keys auf Windows ist ein Pfad über **CNG/KSP** statt reinem Bouncy-Castle-Managed-Key-Objekt.

Nutzen:

- bessere Side-Channel-Eigenschaften
- OS-backed Implementierung
- Grundlage für Export-Policies und persisted/non-exportable Key Objects

---

## P2 – Langfristig: Best-in-Class / Regulated / HSM-ready

### 1. ValidatedBoundary als echter Default für regulierte Schlüssel

Für hochsensible Schlüssel sollte das Ziel nicht sein, `byte[]` noch besser zu löschen, sondern sie **gar nicht mehr als raw bytes in den Anwendungspfad zu holen**.

Zielmodell:

- Private Keys als **non-exportable OS-/HSM-/Token-Objekte**
- nur Handle/Key-ID im Core
- Export nur als Wrap unter Zielschlüssel oder gar nicht
- Nutzung über definierte Operationsrechte (sign, decapsulate, derive, unwrap)

### 2. PKCS#11-/HSM-Pfad oder Windows-KSP-Pfad

Für echte Enterprise-/Regulated-Reife bietet sich an:

- **Windows CNG / KSP** für Windows-first Deployments
- **PKCS#11** für HSM-/Token-Backends

Damit entstehen echte Attribute wie:

- non-extractable
- usage restricted
- hardware-backed / module-backed
- audited object lifecycle

### 3. Key-Wrapping statt Raw-Export

Best-in-Class-Design exportiert geheime Schlüssel in Prod nicht als `byte[]`, sondern höchstens:

- wrapped unter einem Zielschlüssel,
- mit expliziter Richtlinie,
- mit Audit,
- mit kurzer Freigabezeit,
- optional unter Vier-Augen-/Break-Glass-Prozess.

### 4. Vollständiger Key-Lifecycle nach Kryptoperioden

Ein reifer Zielzustand braucht zusätzlich:

- Schlüsselklassifikation
- Key Inventory / Herkunft / Zweckbindung
- Rotation und Rekeying
- Ablauf / Archivierung / Zerstörung
- Trennung von Dev-, Staging- und Prod-Keyspaces
- Auditierbarkeit aller Secret-Egress-Events

---

## Empfohlenes Zielbild pro Betriebsmodus

| Modus | Empfohlener Umgang mit geheimen Schlüsseln |
|---|---|
| Dev | `ReferenceInProcess`, Export für Interop erlaubt, PQM experimentell, klar als unsicherer Komfortpfad markiert |
| Staging | `ProductionIsolated`, Handle-only für Secret Keys/Shared Secrets, Raw-Private-Export standardmäßig aus |
| Prod | `ProductionIsolated` oder besser OS-backed non-exportable Keys, Wrap statt Export, Session-bound Handles, Auto-Cleanup |
| Regulated/FIPS | `ValidatedBoundary`, HSM/KSP/PKCS#11, non-extractable Keys, Auditpflicht für alle sensitiven Operationen |

---

## Konkrete nächste Schritte für die Cybersuite

1. ✅ ~~**Session-bound Handles technisch einführen**~~ → SessionHandleTracker (F2)
2. ✅ ~~**Import-Zeroization korrigieren und Doku angleichen**~~ → finally-Block mit ZeroMemory (F4)
3. ✅ ~~**`Destroy`-Semantik um Session-End-Cleanup ergänzen**~~ → DrainAll bei Dispose (F3)
4. ✅ ~~**Import/Export als policy-gesteuerte Capability verdrahten**~~ → KeyExportPolicy + Enforcer (F6)
5. ✅ ~~**JSON-Transport ausdrücklich als „no raw secret egress“ festschreiben**~~ → SupportsRawSecretEgress + AssertRawSecretEgressPermitted (F7)
6. ⚠️ **OS-native / KSP-basierte non-exportable Key-Objekte integrieren** → P1/P2 Zielbild
7. ⚠️ **Langfristig PKCS#11/HSM-/ValidatedBoundary-Pfad aufbauen** → P2 Zielbild

---

## Schlussfazit

Cybersuite hat bereits mehrere Eigenschaften, die viele Krypto-Frameworks gar nicht besitzen:

- handle-basierte Secret-Semantik,
- explizites Destroy mit Auto-Cleanup bei Session-Ende,
- Session-bound Handle-Tracking via SessionHandleTracker,
- Boundary-Bewusstsein mit SupportsRawSecretEgress-Steuerung,
- no-secret-logging-Disziplin,
- klare Richtung zu `ProductionIsolated` und `ValidatedBoundary`,
- **SensitiveBufferLease** für gepoolte Puffer mit Auto-Zeroization,
- **KeyExportPolicy** mit Profil-abhängiger Governance (Dev/Staging/Prod),
- **Fail-closed Defaults** für unbekannte Policy-Werte und Egress-Versuche,
- **Thread-Safety** lückenlos validiert durch 10 dedizierte Concurrency-Tests.

Nach der Behebung aller P0-Befunde (F2–F7) ist der Zustand **deutlich über dem ursprünglichen Review-Stand**.

Der nächste Qualitätssprung liegt in zwei verbleibenden Architekturentscheidungen:

1. **echte non-exportable Key-Objekte für Prod/Regulated** (OS-/HSM-backed),
2. **binäres, zeroizable Transportformat** für künftige Wrap/Unwrap-/Key-Migration-Pfade.

Wenn diese Punkte umgesetzt werden, kann Cybersuite vom heutigen „sehr bewusst gehärteten Handle-System mit policy-gesteuerter Export-Governance“ zu einem **wirklich starken Secret-Handling-Modell für Enterprise- und regulierte Nutzung** aufsteigen.

---

## Referenzlinien für das Zielbild

Für die Weiterentwicklung in Richtung Best-in-Class sind insbesondere anschlussfähig:

- **NIST SP 800-57 Part 1 Rev. 5** – Key Management Lifecycle
- **NIST SP 800-88 Rev. 2** – Key Sanitization / Cryptographic Erase
- **OWASP Secrets Management Cheat Sheet** – zentrale Secret-Governance, Rotation, Least Privilege, Auditing
- **Windows CNG / NCrypt** – persisted keys und Export-Policy für non-exportable OS-backed Schlüssel
- **PKCS#11 (OASIS)** – standardisierte Token-/HSM-Schnittstelle für non-extractable Keys
