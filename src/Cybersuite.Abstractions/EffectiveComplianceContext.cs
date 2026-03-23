using System.Collections.Immutable;
using System.Security.Cryptography;

namespace Cybersuite.Abstractions;

/// <summary>
/// Single source of truth for the effective compliance posture of a runtime scope.
/// This object contains no secrets. It transports only the canonical, policy-bound decision that
/// must be re-used by Runtime, ProviderHost, Provider sessions, and audit.
/// </summary>
public sealed record EffectiveComplianceContext
{
    /// <summary>Active execution profile (Dev / Staging / Prod) governing security gate strictness.</summary>
    public ExecutionProfile Profile { get; }

    /// <summary>SHA-384 digest of the canonicalized policy bytes. Used for session binding and anti-tampering.</summary>
    public ImmutableArray<byte> PolicyHashSha384 { get; }

    /// <summary>Optional tenant scope from the policy. Null for single-tenant or global policies.</summary>
    public string? TenantId { get; }

    /// <summary>Whether the policy itself requires FIPS-approved algorithms only.</summary>
    public bool PolicyFipsRequired { get; }

    /// <summary>Optional external FIPS override. Null means the policy’s own flag is used; true/false overrides it.</summary>
    public bool? ForceFips { get; }

    /// <summary>Computed effective FIPS requirement: <c>ForceFips ?? PolicyFipsRequired</c>. This is the authoritative value consumed by all downstream gates.</summary>
    public bool EffectiveFipsRequired { get; }

    /// <summary>Whether experimental (non-Stable) algorithm capabilities are admitted into selection.</summary>
    public bool ExperimentalAllowed { get; }

    /// <summary>Minimum provider isolation boundary class required by the compliance posture.</summary>
    public RequiredBoundaryClass RequiredBoundaryClass { get; }

    /// <summary>Set of provider IDs that must be present in the registry. Empty means no mandatory providers.</summary>
    public ImmutableHashSet<ProviderId> RequiredProviderIds { get; }

    /// <summary>Per-provider SHA-256 build hashes for entrypoint integrity verification. Empty means no hash enforcement.</summary>
    public ImmutableDictionary<ProviderId, ImmutableArray<byte>> RequiredBuildHashes { get; }

    /// <summary>Attestation requirement level (None / Optional / Required) for provider trust evaluation.</summary>
    public AttestationRequirement AttestationRequirement { get; }

    /// <summary>
    /// Creates and validates a new effective compliance context.
    /// </summary>
    /// <param name="profile">Active execution profile (Dev / Staging / Prod).</param>
    /// <param name="policyHashSha384">SHA-384 digest of the canonicalized policy. Must be exactly 48 bytes.</param>
    /// <param name="tenantId">Optional tenant scope identifier.</param>
    /// <param name="policyFipsRequired">Whether the policy mandates FIPS-approved algorithms.</param>
    /// <param name="forceFips">Optional external FIPS override (null = use policy flag).</param>
    /// <param name="experimentalAllowed">Whether experimental capabilities are admitted.</param>
    /// <param name="requiredBoundaryClass">Minimum boundary class for provider admission.</param>
    /// <param name="requiredProviderIds">Optional set of mandatory provider IDs.</param>
    /// <param name="requiredBuildHashes">Optional per-provider SHA-256 entrypoint hashes.</param>
    /// <param name="attestationRequirement">Attestation requirement level.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="policyHashSha384"/> is not exactly 48 bytes.</exception>
    public EffectiveComplianceContext(
        ExecutionProfile profile,
        ReadOnlySpan<byte> policyHashSha384,
        string? tenantId,
        bool policyFipsRequired,
        bool? forceFips,
        bool experimentalAllowed,
        RequiredBoundaryClass requiredBoundaryClass,
        ImmutableHashSet<ProviderId>? requiredProviderIds = null,
        ImmutableDictionary<ProviderId, ImmutableArray<byte>>? requiredBuildHashes = null,
        AttestationRequirement attestationRequirement = AttestationRequirement.None)
    {
        if (policyHashSha384.Length != 48)
            throw new ArgumentException("PolicyHashSha384 must be 48 bytes (SHA-384).", nameof(policyHashSha384));

        Profile = profile;
        PolicyHashSha384 = ImmutableArray.CreateRange(policyHashSha384.ToArray());
        TenantId = string.IsNullOrWhiteSpace(tenantId) ? null : tenantId;

        PolicyFipsRequired = policyFipsRequired;
        ForceFips = forceFips;
        EffectiveFipsRequired = forceFips ?? policyFipsRequired;
        ExperimentalAllowed = experimentalAllowed;

        RequiredBoundaryClass = requiredBoundaryClass;
        RequiredProviderIds = requiredProviderIds ?? ImmutableHashSet<ProviderId>.Empty;
        RequiredBuildHashes = requiredBuildHashes ?? ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty;
        AttestationRequirement = attestationRequirement;

        Validate();
    }

    /// <summary>
    /// Validates the internal consistency of this compliance context.
    /// Ensures the policy hash length, FIPS flag derivation, and build hash sizes are correct.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown when any invariant is violated.</exception>
    public void Validate()
    {
        if (PolicyHashSha384.IsDefaultOrEmpty || PolicyHashSha384.Length != 48)
            throw new InvalidOperationException("PolicyHashSha384 must be a 48-byte SHA-384 digest.");

        if (EffectiveFipsRequired != (ForceFips ?? PolicyFipsRequired))
            throw new InvalidOperationException("EffectiveFipsRequired must equal ForceFips ?? PolicyFipsRequired.");

        foreach (var kv in RequiredBuildHashes)
        {
            if (kv.Value.IsDefaultOrEmpty || kv.Value.Length != 32)
                throw new InvalidOperationException(
                    $"Required build hash for provider '{kv.Key.Value}' must be 32 bytes (SHA-256).");
        }
    }

    /// <summary>
    /// Compares this context’s policy hash against another SHA-384 digest using fixed-time comparison
    /// to prevent timing side-channels. Returns false if either hash is invalid or lengths mismatch.
    /// </summary>
    /// <param name="otherPolicyHashSha384">The 48-byte SHA-384 policy hash to compare against.</param>
    /// <returns><c>true</c> if the hashes are cryptographically equal; <c>false</c> otherwise.</returns>
    public bool PolicyHashMatches(ReadOnlySpan<byte> otherPolicyHashSha384)
    {
        if (otherPolicyHashSha384.Length != 48 || PolicyHashSha384.IsDefaultOrEmpty || PolicyHashSha384.Length != 48)
            return false;

        byte[] left = PolicyHashSha384.ToArray();
        bool equal = CryptographicOperations.FixedTimeEquals(left, otherPolicyHashSha384);
        CryptographicOperations.ZeroMemory(left);
        return equal;
    }
}
