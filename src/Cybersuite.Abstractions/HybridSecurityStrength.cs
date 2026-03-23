namespace Cybersuite.Abstractions;

/// <summary>
/// Security strength for hybrid (classical + post-quantum) algorithm compositions.
/// Per the crypto-agile architecture [ARC-202], hybrid algorithms combine a classical component
/// (e.g. ECDH-P384) with a post-quantum component (e.g. ML-KEM-768) to provide defense-in-depth.
/// The <see cref="Effective"/> strength is the minimum of both, following the "weakest link" principle.
/// </summary>
public readonly record struct HybridSecurityStrength(
    SecurityStrength Classical,
    SecurityStrength PostQuantum)
{
    public SecurityStrength Effective => new(Math.Min(Classical.Bits, PostQuantum.Bits));
}