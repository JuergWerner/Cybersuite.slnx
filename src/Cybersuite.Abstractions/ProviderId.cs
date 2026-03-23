namespace Cybersuite.Abstractions;

/// <summary>
/// Strongly-typed, immutable identifier for a cryptographic provider (e.g. "BouncyCastle").
/// Providers are the concrete units that supply algorithm implementations.
/// Used for provider allowlisting, pinning, trust evaluation, and session binding [ARC-300].
/// Value semantics: two ProviderId instances are equal when their string values match.
/// </summary>
public readonly record struct ProviderId(string Value)
{
    public override string ToString() => Value ?? string.Empty;
}