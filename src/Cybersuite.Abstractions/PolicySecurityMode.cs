namespace Cybersuite.Abstractions;

/// <summary>
/// Policy-level security mode that dictates which <see cref="AlgorithmSecurityMode"/> values
/// are acceptable for asymmetric algorithm categories (KEM, KeyExchange, Signature).
/// Defined in [ARC-030] and enforced by the selection engine [SEL-000].
/// 
/// Mapping rules (strict, no implicit fallback):
/// - <see cref="Classical"/>: only <see cref="AlgorithmSecurityMode.Classical"/> algorithms accepted.
/// - <see cref="Pqc"/>: only <see cref="AlgorithmSecurityMode.Pqc"/> algorithms accepted.
/// - <see cref="Hybrid"/>: only <see cref="AlgorithmSecurityMode.Hybrid"/> algorithms accepted.
/// 
/// This strict mapping is the primary anti-downgrade mechanism: a policy set to Hybrid
/// cannot silently fall back to Classical-only algorithms, even if they are available
/// with higher strength values. This prevents downgrade attacks at the policy level.
/// 
/// Symmetric categories (AEAD, KDF, Hash, etc.) are not filtered by this mode.
/// </summary>
public enum PolicySecurityMode
{
    /// <summary>Classical-only policy: accept only pre-quantum algorithms for asymmetric categories.</summary>
    Classical = 0,

    /// <summary>PQC-only policy: accept only post-quantum algorithms for asymmetric categories.</summary>
    Pqc = 1,

    /// <summary>Hybrid policy: accept only combined Classical+PQC algorithms for asymmetric categories.</summary>
    Hybrid = 2
}