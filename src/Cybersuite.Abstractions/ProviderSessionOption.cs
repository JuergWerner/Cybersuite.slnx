namespace Cybersuite.Abstractions;

/// <summary>
/// Options used when opening a provider session from the Runtime or ProviderHost layers.
/// Includes the SHA-384 policy hash for session binding verification, FIPS requirements,
/// and optional tenant isolation. Wave 1 adds the canonical effective compliance context
/// without breaking callers that still use the legacy fields only.
/// </summary>
public sealed record ProviderSessionOptions(
    ReadOnlyMemory<byte> BoundPolicyHash,
    bool FipsRequired,
    string? TenantId = null,
    EffectiveComplianceContext? EffectiveCompliance = null);
