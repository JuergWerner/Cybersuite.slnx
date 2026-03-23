namespace Cybersuite.Abstractions;

/// <summary>
/// Encoding profile used for import/export and interoperability.
/// Not every profile is valid for every algorithm.
/// Providers may reject unsupported combinations fail-closed.
/// </summary>
public enum AlgorithmEncodingProfile
{
    /// <summary>Provider-native encoding (default). Format is provider-defined and may not be interoperable.</summary>
    ProviderNative = 0,

    // --- Standardized public/private key containers ---

    /// <summary>X.509 SubjectPublicKeyInfo (DER/BER) — standard interoperable public key encoding per RFC 5280.</summary>
    SubjectPublicKeyInfo = 1,

    /// <summary>PKCS#8 PrivateKeyInfo (DER/BER) — standard interoperable private key encoding per RFC 5958.</summary>
    Pkcs8PrivateKey = 2,

    // --- Raw / provider-specific forms ---

    /// <summary>Raw public key bytes without ASN.1 wrapper (e.g. uncompressed EC point, raw ML-KEM public key).</summary>
    RawPublicKey = 10,

    /// <summary>Raw private key bytes without ASN.1 wrapper. Caller must handle zeroization.</summary>
    RawPrivateKey = 11,

    // --- PQC-relevant variants ---

    /// <summary>Seed-only private key (compact PQC form — the full key is re-expanded from the seed at use time).</summary>
    SeedOnlyPrivateKey = 20,

    /// <summary>Fully expanded private key (pre-computed PQC form — avoids re-expansion cost at signing/decapsulation time).</summary>
    ExpandedPrivateKey = 21
}