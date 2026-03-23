namespace Cybersuite.Abstractions;

/// <summary>
/// Strongly-typed, immutable identifier for a cryptographic algorithm (e.g. "ML-KEM-768", "AES-256-GCM").
/// Used throughout the Cybersuite architecture as the canonical key for algorithm selection,
/// capability matching, and policy enforcement [ARC-200].
/// Value semantics: two AlgorithmId instances are equal when their string values match.
/// </summary>
public readonly record struct AlgorithmId(string Value)
{
    public override string ToString() => Value ?? string.Empty;
}