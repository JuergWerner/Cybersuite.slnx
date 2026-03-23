namespace Cybersuite.Abstractions;

/// <summary>
/// Canonical cryptographic algorithm classification.
/// This enum is a Stage-1 invariant and may only be extended additively.
/// </summary>
public enum AlgorithmCategory
{
    // --- Asymmetric primitives ---

    /// <summary>Key Encapsulation Mechanism (e.g. ML-KEM / Kyber, ECDH-KEM). Subject to <see cref="PolicySecurityMode"/> anti-downgrade filtering.</summary>
    KeyEncapsulation,

    /// <summary>Key Exchange (e.g. ECDH, X25519). Subject to <see cref="PolicySecurityMode"/> anti-downgrade filtering.</summary>
    KeyExchange,

    /// <summary>Digital Signature (e.g. ML-DSA / Dilithium, ECDSA). Subject to <see cref="PolicySecurityMode"/> anti-downgrade filtering.</summary>
    Signature,

    /// <summary>Authentication primitive (e.g. HMAC-based entity authentication). Subject to <see cref="PolicySecurityMode"/> anti-downgrade filtering.</summary>
    Authentication,

    // --- Symmetric primitives ---

    /// <summary>Symmetric Authenticated Encryption with Associated Data (e.g. AES-256-GCM, ChaCha20-Poly1305). Not subject to security mode filtering.</summary>
    SymmetricAead,

    /// <summary>Message Authentication Code (e.g. HMAC-SHA384). Not subject to security mode filtering.</summary>
    Mac,

    /// <summary>Cryptographic hash function (e.g. SHA-384, SHA3-256). Not subject to security mode filtering.</summary>
    Hash,

    /// <summary>Key Derivation Function (e.g. HKDF-SHA384). Not subject to security mode filtering.</summary>
    KeyDerivation,

    // --- Entropy / RNG ---

    /// <summary>Random number / entropy source (e.g. OS CSPRNG). Not subject to security mode filtering.</summary>
    Random
}