namespace Cybersuite.Abstractions;

/// <summary>
/// Identifies a concrete algorithm parameter set, e.g.:
/// - ML-KEM-512 / ML-KEM-768 / ML-KEM-1024
/// - ML-DSA-44 / ML-DSA-65 / ML-DSA-87
/// - SLH-DSA-SHA2-128f
/// 
/// This is distinct from AlgorithmId:
/// - AlgorithmId = logical algorithm family / provider-exposed identifier
/// - AlgorithmParameterSetId = concrete standard parameter profile
/// </summary>
public readonly record struct AlgorithmParameterSetId(string Value)
{
    public override string ToString() => Value;
}