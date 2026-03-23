# Cybersuite Dokumentation

Willkommen zur Dokumentation der Cybersuite - einem Post-Quantum Cryptography Provider Framework für .NET 10.

---

## ⚠️ WICHTIG: Beta-Software

**Diese Suite verwendet BouncyCastle 2.7.0-beta.98 (experimentell) und ist NICHT für Production geeignet.**

📋 **Bitte lesen Sie zuerst:** [Beta-Software Warnung](BETA-WARNING.md)

---

## 📚 Dokumentations-Übersicht

### 1. [🚀 Schnellstart-Anleitung](QUICKSTART.md)
**Für Einsteiger** - 5-Minuten-Einführung

- Projekt Setup
- Erstes ML-KEM Programm
- Praktische Beispiele
- Troubleshooting

📖 **Start here:** [QUICKSTART.md](QUICKSTART.md)

---

### 2. [📖 Vollständige Dokumentation](README.md)
**Für Entwickler** - Detaillierte technische Referenz

- Architektur & Design
- Alle unterstützten Algorithmen
- API-Dokumentation
- NIST Test Vector Validation
- Performance Benchmarks
- Best Practices

📖 **Deep dive:** [README.md](README.md)

---

### 3. [⚠️ Beta-Software Warnung](BETA-WARNING.md)
**Für alle** - Risiken und Einschränkungen

- Status & Risiken
- Production-Use Warnung
- Geeignete Anwendungsfälle
- Aktualisierungsstrategie
- Risiko-Mitigation

📖 **Wichtig:** [BETA-WARNING.md](BETA-WARNING.md)

---

## 🎯 Schnellnavigation

### Ich möchte...

| Ziel | Dokument | Abschnitt |
|------|----------|-----------|
| **Schnell starten** | [QUICKSTART.md](QUICKSTART.md) | Schnellstart in 5 Minuten |
| **ML-KEM verwenden** | [QUICKSTART.md](QUICKSTART.md) | Beispiel 1: Sichere Nachrichtenübertragung |
| **ML-DSA verwenden** | [QUICKSTART.md](QUICKSTART.md) | Beispiel 2: Dokument signieren |
| **Architektur verstehen** | [README.md](README.md) | Architektur → Schichtenmodell |
| **Test-Vektoren laden** | [README.md](README.md) | NIST Test Vector Validation |
| **Algorithmen vergleichen** | [README.md](README.md) | Unterstützte Algorithmen |
| **Performance-Daten sehen** | [README.md](README.md) | Performance |
| **Risiken verstehen** | [BETA-WARNING.md](BETA-WARNING.md) | Risiken & Einschränkungen |
| **Production-Readiness prüfen** | [BETA-WARNING.md](BETA-WARNING.md) | Checkliste |
| **Hybrid-Crypto nutzen** | [QUICKSTART.md](QUICKSTART.md) | Beispiel 3: Hybrid KEM |

---

## 🛠️ Technologie-Stack

```
.NET 10
├── Cybersuite.Abstractions         (Krypto-Schnittstellen, Basis-Typen & SensitiveBufferLease)
├── Cybersuite.Policy               (Policy-Laden, Validierung, Signaturen)
├── Cybersuite.Selection            (Algorithmen-Auswahl bei Policy-Verstoß)
├── Cybersuite.ProviderModel        (Provider-Deskriptoren & Isolation)
├── Cybersuite.OopProtocol          (Out-of-Process Protokoll)
├── Cybersuite.ProviderHost         (Provider Discovery, Trust, Launch, KeyExportPolicy)
├── Cybersuite.Compliance           (Compliance-Gates & Dual-Prüfung)
├── Cybersuite.Runtime              (Top-Level Orchestrierung & Audit)
└── Cybersuite.Provider.BouncyCastle (PQC- & klassische Implementierung)
    └── BouncyCastle.Cryptography 2.7.0-beta.98 ⚠️
```

---

## 📋 Wichtige Links

### Standards & Spezifikationen
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST PQC Project](https://csrc.nist.gov/Projects/post-quantum-cryptography)

### Software & Libraries
- [BouncyCastle C#](https://github.com/bcgit/bc-csharp)
- [NIST ACVP Server](https://github.com/usnistgov/ACVP-Server)
- [xUnit.net](https://xunit.net/)

### Repository
- [Cybersuite GitHub](https://github.com/JuergWerner/Cybersuite)

---

## 🔧 Projekt-Struktur

```
Cybersuite/
├── docs/                              # 📚 Sie sind hier
│   ├── INDEX.md                       # Diese Datei
│   ├── ARCHITECTURE_CANON.md          # Architektur-Kanon (AC-1.7.0)
│   ├── QUICKSTART.md                  # Schnellstart-Anleitung
│   ├── README.md                      # Vollständige Dokumentation
│   └── BETA-WARNING.md                # Beta-Warnung
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
│   ├── Cybersuite.Test.Property/      # Property-Based Tests
│   ├── Cybersuite.Tests.Compliance/   # Compliance Tests
│   ├── Cybersuite.Tests.Integration/  # Integration Tests
│   └── TestVectors/                   # NIST Test Vectors
│       └── ML-KEM/
│           ├── download-vectors.ps1   # Download-Script
│           └── README.md              # Test Vector Doku
└── Cybersuite.slnx.slnx              # Solution-Datei
```

---

## ✅ Quick Start Checkliste

Bevor Sie beginnen:

- [ ] Gelesen: [Beta-Software Warnung](BETA-WARNING.md)
- [ ] Verstanden: Nicht für Production
- [ ] Installiert: .NET 10 SDK
- [ ] Installiert: BouncyCastle.Cryptography 2.7.0-beta.98
- [ ] Heruntergeladen: NIST Test-Vektoren

**Dann starten Sie mit:** [QUICKSTART.md](QUICKSTART.md)

---

## 🆘 Hilfe & Support

### Dokumentation nicht klar?

1. Prüfen Sie [Troubleshooting in QUICKSTART.md](QUICKSTART.md#troubleshooting)
2. Lesen Sie [Häufige Fehler in README.md](README.md#troubleshooting)
3. Öffnen Sie ein [GitHub Issue](https://github.com/JuergWerner/Cybersuite/issues)

### Fehler gefunden?

1. Prüfen Sie ob es ein [bekanntes Problem](README.md#troubleshooting) ist
2. Reproduzieren Sie den Fehler
3. Erstellen Sie ein [GitHub Issue](https://github.com/JuergWerner/Cybersuite/issues) mit Details

### Feature-Wunsch?

1. Prüfen Sie die [Roadmap](README.md#roadmap)
2. Öffnen Sie ein [Feature Request](https://github.com/JuergWerner/Cybersuite/issues)

---

## 📊 Status-Übersicht

| Komponente | Status | Dokumentation |
|------------|--------|---------------|
| ML-KEM (FIPS 203) | ✅ Implementiert | [README.md](README.md#ml-kem) |
| ML-DSA (FIPS 204) | ✅ Implementiert | [README.md](README.md#ml-dsa) |
| ECDH-P384 | ✅ Implementiert | [README.md](README.md#klassische-kryptografie) |
| ECDSA-P384 | ✅ Implementiert | [README.md](README.md#klassische-kryptografie) |
| AES-256-GCM | ✅ Implementiert | [README.md](README.md#verschlüsselung) |
| HKDF-SHA384 | ✅ Implementiert | [README.md](README.md#key-derivation) |
| NIST Test Vectors | ✅ ML-KEM validiert | [README.md](README.md#nist-test-vector-validation) |
| Integration Tests | ✅ Alle Tests bestehen | [README.md](README.md#tests-ausführen) |
| Key-Import/Export | ✅ Implementiert | [README.md](README.md#key-import-export) |
| ILogger<T> Logging | ✅ Implementiert | [README.md](README.md#logging) |
| NativeCurveP384 | ✅ Implementiert | [README.md](README.md#native-ecdh) |
| Nonce-State-Machine | ✅ Implementiert | [README.md](README.md#nonce-safety) |
| SensitiveBufferLease | ✅ Implementiert | [ARCHITECTURE_CANON.md](ARCHITECTURE_CANON.md#sec-sc-001) |
| SessionHandleTracker | ✅ Implementiert | [ARCHITECTURE_CANON.md](ARCHITECTURE_CANON.md#sec-thr-000) |
| Thread-Safety Hardening | ✅ Dispose-Guards, Concurrent Tests | [ARCHITECTURE_CANON.md](ARCHITECTURE_CANON.md#sec-thr-000) |
| KeyExportPolicy Governance | ✅ Profil-abhängig, fail-closed | [ARCHITECTURE_CANON.md](ARCHITECTURE_CANON.md#sec-ke-000) |
| Handle-Only Secret Egress | ✅ Durchgesetzt | [ARCHITECTURE_CANON.md](ARCHITECTURE_CANON.md#sec-eg-000) |
| Security Audit | ✅ Alle P0 behoben | [umgang-mit-geheimen-schluesseln](../audits/ChatGPT/umgang-mit-geheimen-schluesseln-in-der-suit.md) |
| Production Ready | ❌ Nein (Beta) | [BETA-WARNING.md](BETA-WARNING.md) |

---

## 🎓 Lernpfad

### Level 1: Anfänger
1. Lesen Sie [BETA-WARNING.md](BETA-WARNING.md)
2. Folgen Sie [QUICKSTART.md](QUICKSTART.md)
3. Führen Sie die Beispiele aus

### Level 2: Fortgeschrittene
1. Studieren Sie [README.md → Architektur](README.md#architektur)
2. Verstehen Sie [OOP Protocol](README.md#out-of-process-protocol)
3. Experimentieren Sie mit verschiedenen Algorithmen

### Level 3: Experten
1. Tauchen Sie ein in [Reflection-basierte PQC-Unterstützung](README.md#reflection-basierte-pqc-unterstützung)
2. Validieren Sie gegen [NIST Test Vectors](README.md#nist-test-vector-validation)
3. Implementieren Sie eigene Provider

---

## 📅 Versionshistorie

| Version | Datum | Highlights |
|---------|-------|------------|
| 1.0.0 | März 2025 | Initiales Release mit ML-KEM/ML-DSA |
| 1.1.0 | Juli 2025 | Security-Audit behoben, ILogger, Key-Import/Export, NativeCurveP384, Nonce-Strategy |
| 1.2.0 | März 2026 | Thread-Safety-Hardening, SensitiveBufferLease, KeyExportPolicy, Handle-Only-Egress, SessionHandleTracker, Dead-Code-Bereinigung |

---

## 📜 Lizenz

Proprietär - Für interne Verwendung

Copyright © 2024-2026 Jürg Werner

---

**Viel Erfolg mit Cybersuite! 🚀**

*Letzte Aktualisierung: Juli 2025*