using System.Collections.Immutable;
using System.Security.Cryptography;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Minimum information needed to bind an OOP provider session to a policy/profile,
/// without referencing Policy internals. Wave 1 adds the canonical effective compliance context
/// while preserving the existing binding fields for additive evolution.
/// </summary>
public sealed record ProviderSessionBinding
{
    /// <summary>SHA-384 digest of canonical policy bytes (48 bytes).</summary>
    public required ImmutableArray<byte> PolicyHashSha384 { get; init; }

    public required ExecutionProfile ExecutionProfile { get; init; }

    public bool FipsRequired { get; init; }

    public bool ExperimentalAllowed { get; init; }

    public string? TenantId { get; init; }

    public ProviderId? ExpectedProviderId { get; init; }

    public string? ExpectedBuildHash { get; init; }

    /// <summary>
    /// Canonical single source of truth for compliance admission. Optional for backward compatibility,
    /// but always expected on the Runtime path from Wave 1 onward.
    /// </summary>
    public EffectiveComplianceContext? EffectiveCompliance { get; init; }

    public void Validate()
    {
        if (PolicyHashSha384.IsDefaultOrEmpty || PolicyHashSha384.Length != 48)
            throw new ArgumentException("PolicyHashSha384 must be 48 bytes (SHA-384).", nameof(PolicyHashSha384));

        if (EffectiveCompliance is not null)
        {
            EffectiveCompliance.Validate();

            if (!FixedTimePolicyHashEquals(PolicyHashSha384, EffectiveCompliance.PolicyHashSha384))
            {
                throw new InvalidOperationException(
                    "ProviderSessionBinding.PolicyHashSha384 must match EffectiveCompliance.PolicyHashSha384.");
            }
        }
    }

    private static bool FixedTimePolicyHashEquals(ImmutableArray<byte> left, ImmutableArray<byte> right)
    {
        if (left.IsDefaultOrEmpty || right.IsDefaultOrEmpty || left.Length != 48 || right.Length != 48)
            return false;

        byte[] a = left.ToArray();
        byte[] b = right.ToArray();
        bool equal = CryptographicOperations.FixedTimeEquals(a, b);
        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(b);
        return equal;
    }
}
