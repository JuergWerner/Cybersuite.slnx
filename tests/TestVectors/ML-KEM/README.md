# ML-KEM (FIPS 203) Test Vectors

This directory contains test vectors for ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism), standardized as **FIPS 203**.

## Official Sources

### 1. NIST ACVP Server (Recommended)
Official test vectors from the NIST Automated Cryptographic Validation Protocol:
- **Repository**: https://github.com/usnistgov/ACVP-Server
- **ML-KEM Vectors**: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

### 2. NIST FIPS 203 Standard
- **FIPS 203 PDF**: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- **CSRC Page**: https://csrc.nist.gov/pubs/fips/203/final

### 3. BouncyCastle Test Vectors
- **Repository**: https://github.com/bcgit/bc-csharp
- **Test Data**: https://github.com/bcgit/bc-csharp/tree/master/crypto/test/data/pqc

## Directory Structure

```
ML-KEM/
├── README.md                          (this file)
├── download-vectors.ps1               (automated download script)
├── ML-KEM-512/
│   ├── keyGen.json
│   ├── encapDecap.json
│   └── kat.rsp
├── ML-KEM-768/
│   ├── keyGen.json
│   ├── encapDecap.json
│   └── kat.rsp
└── ML-KEM-1024/
    ├── keyGen.json
    ├── encapDecap.json
    └── kat.rsp
```

## Automated Download

Run the PowerShell script to automatically download all test vectors:

```powershell
cd tests/TestVectors/ML-KEM
.\download-vectors.ps1
```

## Manual Download

### NIST ACVP JSON Format

**ML-KEM-512:**
```powershell
# Key Generation
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json" -OutFile "ML-KEM-512/keyGen.json"

# Encapsulation/Decapsulation
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json" -OutFile "ML-KEM-512/encapDecap.json"
```

**ML-KEM-768:**
```powershell
# Same pattern for ML-KEM-768 parameters
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json" -OutFile "ML-KEM-768/keyGen.json"
```

**ML-KEM-1024:**
```powershell
# Same pattern for ML-KEM-1024 parameters
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json" -OutFile "ML-KEM-1024/keyGen.json"
```

### Known Answer Tests (KAT)

NIST provides Known Answer Test files in `.rsp` format for each parameter set.

## Test Vector Format

### NIST ACVP JSON Format
```json
{
  "vsId": 0,
  "algorithm": "ML-KEM",
  "mode": "keyGen",
  "testGroups": [
    {
      "tgId": 1,
      "testType": "AFT",
      "parameterSet": "ML-KEM-512",
      "tests": [
        {
          "tcId": 1,
          "d": "...",
          "z": "...",
          "ek": "...",
          "dk": "..."
        }
      ]
    }
  ]
}
```

### KAT Response Format (.rsp)
```
# ML-KEM-512

count = 0
z = ...
d = ...
ek = ...
dk = ...
c = ...
k = ...
```

## Integration with Tests

See `Cybersuite.Tests.Integration` for usage examples:
- `LiveCryptoRoundTripTests.cs` - Live roundtrip tests for all algorithms
- `MlKemTestVectorTests.cs` - NIST FIPS 203 test vector validation (keyGen + encapDecap)

## References

1. **FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard
   - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

2. **NIST PQC Project**:
   - https://csrc.nist.gov/Projects/post-quantum-cryptography

3. **ACVP Specification**:
   - https://pages.nist.gov/ACVP/

## Notes

- Test vectors are **not** committed to Git due to size (see `.gitignore`)
- Run `download-vectors.ps1` after cloning the repository
- Vectors should be validated against FIPS 203 appendices
- BouncyCastle implementation may have slight differences in encoding

## License

Test vectors are public domain (US Government work).
