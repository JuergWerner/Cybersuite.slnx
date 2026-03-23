# ⚠️ Beta-Software Warnung

## Status: Experimentell / Nicht Production-Ready

**Stand:** März 2026

---

## Verwendete Beta-Software

### BouncyCastle.Cryptography 2.7.0-beta.98

Cybersuite basiert auf einer **experimentellen Beta-Version** von BouncyCastle.Cryptography, die erforderlich ist für:

- **ML-KEM (FIPS 203)** - Module-Lattice-Based Key-Encapsulation Mechanism
- **ML-DSA (FIPS 204)** - Module-Lattice-Based Digital Signature Algorithm

### Warum Beta?

Die stable Release-Versionen von BouncyCastle (z.B. 2.4.0) enthalten:
- ❌ Keine vollständige Unterstützung für die neuen ML-KEM/ML-DSA APIs
- ❌ Keine BouncyCastle 2.0+ API-Struktur für PQC
- ❌ Fehlende FIPS 203/204 Konformität

Die Beta-Version 2.7.0+ bietet:
- ✅ Vollständige ML-KEM und ML-DSA Implementierungen
- ✅ NIST FIPS 203/204 konforme APIs
- ✅ Neue Constructor-basierte Parameterübergabe
- ✅ Aktuelle Namespace-Struktur (`Org.BouncyCastle.Crypto.*`)

---

## Risiken & Einschränkungen

### 🔴 Production-Use Nicht Empfohlen

**VERWENDEN SIE DIESE SOFTWARE NICHT IN:**

1. **Kritischen Infrastrukturen**
   - Finanzielle Transaktionssysteme
   - Gesundheitssysteme
   - Regierungs- und Behördensysteme
   - Kritische Industriesteuerungen

2. **Produktiven Systemen**
   - Live-Webanwendungen mit echten Benutzern
   - Mobile Apps im Store
   - SaaS-Plattformen
   - Enterprise-Authentifizierung

3. **Echter Datenverschlüsselung**
   - Verschlüsselung sensibler Kundendaten
   - Langzeit-Archivierung
   - Compliance-relevante Daten (DSGVO, HIPAA, etc.)

### ⚠️ Bekannte Risiken

#### 1. API-Stabilität
- **Problem:** Beta-APIs können sich ändern
- **Auswirkung:** Breaking Changes in zukünftigen Versionen
- **Mitigation:** Testen Sie jede neue Version gründlich

#### 2. Kryptografische Sicherheit
- **Problem:** Beta-Implementierungen können Bugs enthalten
- **Auswirkung:** Potenzielle Sicherheitslücken in PQC-Algorithmen
- **Mitigation:** 
  - Verwenden Sie Hybrid-Ansätze (klassisch + PQC)
  - Validieren Sie gegen NIST Test Vectors
  - Überwachen Sie Security Advisories

#### 3. Performance
- **Problem:** Beta-Code ist nicht vollständig optimiert
- **Auswirkung:** Langsamere Operationen als finale Version
- **Mitigation:** Performance-Tests durchführen, wenn relevant

#### 4. Stabilität
- **Problem:** Potenzielle Crashes oder unerwartetes Verhalten
- **Auswirkung:** Produktionsausfälle möglich
- **Mitigation:** Umfangreiche Tests, Exception Handling

#### 5. Support & Updates
- **Problem:** Beta-Versionen werden möglicherweise nicht langfristig unterstützt
- **Auswirkung:** Keine Patches für alte Beta-Versionen
- **Mitigation:** Regelmäßig auf neueste Beta aktualisieren

---

## ✅ Geeignete Anwendungsfälle

### Forschung & Entwicklung

```
✅ Akademische Forschung zu PQC
✅ Universitätsprojekte
✅ Kryptografische Analysen
✅ Algorithmus-Vergleiche
```

### Prototyping

```
✅ Proof-of-Concepts
✅ Technologie-Evaluationen
✅ Architektur-Demos
✅ Machbarkeitsstudien
```

### Testing & Evaluation

```
✅ NIST Test Vector Validierung
✅ Performance Benchmarks
✅ Kompatibilitätstests
✅ Security Audits (Pre-Production)
```

### Migration-Vorbereitung

```
✅ Post-Quantum Migration Planning
✅ Team-Training
✅ Hybrid-Crypto Strategie-Tests
✅ Interoperabilitäts-Tests
```

---

## 🔄 Aktualisierungsstrategie

### Überwachen Sie Releases

Behalten Sie folgende Quellen im Auge:

1. **BouncyCastle Releases**
   - GitHub: https://github.com/bcgit/bc-csharp/releases
   - NuGet: https://www.nuget.org/packages/BouncyCastle.Cryptography
   
2. **NIST PQC Updates**
   - https://csrc.nist.gov/Projects/post-quantum-cryptography
   - FIPS 203/204 Errata & Updates

3. **Cybersuite Updates**
   - Eigenes Repository: https://github.com/JuergWerner/Cybersuite

### Update-Prozess

```bash
# 1. Aktuelle Packages überprüfen
dotnet list package --include-prerelease

# 2. Auf neuere Beta aktualisieren
dotnet add package BouncyCastle.Cryptography --version 2.7.0-beta.XX

# 3. Alle Tests ausführen
dotnet test

# 4. NIST Test Vectors re-validieren
cd tests\TestVectors\ML-KEM
.\download-vectors.ps1
dotnet test --filter "MlKemTestVectorTests"
```

### Wann auf Stable wechseln?

Migrieren Sie zu einer stable Release, wenn:

- ✅ BouncyCastle veröffentlicht eine stable 2.x Version
- ✅ Keine Breaking Changes in den APIs
- ✅ Alle Tests bestehen
- ✅ NIST Standardisierung abgeschlossen (FIPS 203/204 final)
- ✅ Keine kritischen Issues in Release Notes

---

## 📋 Checkliste: Ist Cybersuite für mich geeignet?

Beantworten Sie folgende Fragen:

- [ ] Ist dies ein Forschungs-/Entwicklungsprojekt (nicht Production)?
- [ ] Bin ich bereit, regelmäßig auf neuere Beta-Versionen zu aktualisieren?
- [ ] Habe ich ein Test-Framework für Breaking Changes?
- [ ] Verstehe ich die Risiken von Beta-Software?
- [ ] Verwende ich Hybrid-Kryptografie (klassisch + PQC)?
- [ ] Validiere ich gegen NIST Test Vectors?
- [ ] Plane ich für eine spätere Migration auf Stable-Releases?

**Wenn Sie alle Fragen mit JA beantwortet haben:** ✅ Cybersuite ist geeignet

**Wenn Sie eine Frage mit NEIN beantwortet haben:** ❌ Warten Sie auf Stable Releases

---

## 🛡️ Risiko-Mitigation Strategien

### 1. Hybrid-Kryptografie verwenden

Kombinieren Sie **klassische + PQC** Algorithmen:

```csharp
// Verwenden Sie ECDH-P384 + ML-KEM-768 gleichzeitig
var ecdhSecret = await PerformECDH(...);
var mlkemSecret = await PerformMLKEM(...);
var finalSecret = HKDF.Derive(ecdhSecret, mlkemSecret);
```

**Vorteil:** Sicherheit bleibt erhalten, auch wenn PQC-Implementierung fehlerhaft ist.

### 2. Umfangreiche Tests

```csharp
// Validieren Sie gegen NIST Test Vectors
dotnet test --filter "MlKemTestVectorTests"
dotnet test --filter "LiveCryptoRoundTripTests"

// Eigene Tests für Ihre Use-Cases
```

### 3. Fehlerbehandlung

```csharp
try
{
    var result = await conn.KemEncapsulateAsync(...);
}
catch (NotSupportedException ex)
{
    // Fallback auf klassische Kryptografie
    _logger.LogError(ex, "ML-KEM not supported, falling back to ECDH");
    var result = await conn.KemEncapsulateAsync(ecdhAlg, ...);
}
```

### 4. Feature-Flags

```csharp
// Konfigurierbar aktivieren/deaktivieren
var usePQC = configuration.GetValue<bool>("Crypto:EnablePostQuantum");

var algorithm = usePQC 
    ? new AlgorithmId("ML-KEM-768") 
    : new AlgorithmId("ECDH-P384");
```

### 5. Monitoring & Logging

```csharp
// Überwachen Sie kryptografische Operationen
_telemetry.TrackEvent("CryptoOperation", new Dictionary<string, string>
{
    { "Algorithm", "ML-KEM-768" },
    { "Operation", "Encapsulate" },
    { "Success", result.Success.ToString() }
});
```

---

## 📞 Hilfe & Support

### Bei Problemen mit Beta-Software

1. **BouncyCastle Issues:** https://github.com/bcgit/bc-csharp/issues
2. **Cybersuite Issues:** https://github.com/JuergWerner/Cybersuite/issues
3. **NIST PQC Forum:** https://csrc.nist.gov/Projects/post-quantum-cryptography/email-list

### Vor Production-Einsatz

Konsultieren Sie:
- Kryptografie-Experten
- Security Auditors
- Compliance Officers
- Ihre IT-Security-Abteilung

---

## 🎯 Zusammenfassung

| Aspekt | Status |
|--------|--------|
| **Software-Status** | ⚠️ Experimentelle Beta |
| **Production Ready** | ❌ Nein (Stand: März 2026) |
| **Für R&D geeignet** | ✅ Ja |
| **Breaking Changes möglich** | ⚠️ Ja |
| **NIST-konform** | ✅ Ja (FIPS 203/204) |
| **Security-Audit** | ✅ Alle P0 Findings behoben (F2–F7) |
| **Tests** | ✅ 200+ bestanden (inkl. Thread-Safety & Egress-Guard) |
| **Support-Level** | ⚠️ Community (Beta) |
| **Empfohlene Aktion** | 📋 Auf Stable Release warten |

---

**Datum:** März 2026  
**Nächste Review:** Nach BouncyCastle 2.x Stable Release (voraussichtlich 2026)  
**Dokument-Version:** 1.2