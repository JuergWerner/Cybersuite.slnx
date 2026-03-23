namespace Cybersuite.Abstractions;

/// <summary>
/// Classifies whether an algorithm is Classical-only, PQC-only, or Hybrid (Classical+PQC combined).
/// Defined in [ARC-030] as part of the Algorithm Descriptor model.
/// 
/// Used by the selection engine to enforce the anti-downgrade invariant:
/// when the policy mandates PQC or Hybrid mode, no classical-only algorithm may be selected
/// for asymmetric categories (KEM, KeyExchange, Signature). This prevents silent downgrade
/// attacks that could strip post-quantum protection.
/// 
/// Symmetric categories (AEAD, KDF, Hash, Mac, Random) are not subject to this mode check
/// because they do not have a PQC/classical distinction at the algorithm level.
/// </summary>
public enum AlgorithmSecurityMode
{
    /// <summary>Traditional / pre-quantum cryptography (e.g., RSA, ECDSA, ECDH).</summary>
    Classical = 0,

    /// <summary>Post-Quantum Cryptography only (e.g., ML-KEM, ML-DSA).</summary>
    Pqc = 1,

    /// <summary>Hybrid: combined Classical + PQC construction (e.g., X25519 + ML-KEM-768).</summary>
    Hybrid = 2
}