using System.Collections.Immutable;

namespace Cybersuite.Abstractions;

/// <summary>
/// Immutable, read-only policy snapshot contract. Central to [ARC-030] (Snapshot-Philosophie)
/// and [POL-000] (Policy Integrity & Signature Model).
/// 
/// A policy defines the security posture for algorithm selection:
/// - Which security mode to enforce (Classical / PQC / Hybrid).
/// - Minimum strength requirements per algorithm category.
/// - Provider allowlists and pinning rules.
/// - FIPS compliance requirements.
/// 
/// Implementations must be immutable and thread-safe. The canonical implementation is
/// <see cref="Policy.PolicySnapshot"/>, produced by the PolicyLoader from signed/validated JSON.
/// 
/// The <see cref="PolicyHash"/> is the SHA-384 digest of the canonicalized policy bytes
/// (excluding the signature envelope). It is used for:
/// - Signature verification (the signature covers canonical bytes).
/// - OOP handshake binding (<see cref="OopProtocol.Handshake.ClientHello.PolicyHashSha384"/>).
/// - Anti-tampering: any change to the policy produces a different hash.
/// 
/// Anti-rollback: <see cref="Sequence"/> is monotonically increasing. The PolicyLoader
/// rejects policies with a sequence below the configured minimum.
/// </summary>
public interface IPolicy
{
    /// <summary>Schema version string for forward/backward compatibility detection.</summary>
    string SchemaVersion { get; }

    /// <summary>
    /// Monotonic policy sequence for anti-rollback protection.
    /// The PolicyLoader rejects policies whose sequence is below the configured minimum.
    /// </summary>
    long Sequence { get; }

    /// <summary>
    /// Optional tenant scope. Empty/Null means single-tenant or global policy.
    /// Multi-tenant deployments use this to scope policy constraints per tenant.
    /// </summary>
    string? TenantId { get; }

    /// <summary>
    /// Governs which <see cref="AlgorithmSecurityMode"/> values are allowed for asymmetric categories.
    /// See <see cref="PolicySecurityMode"/> for the strict mapping rules (anti-downgrade).
    /// </summary>
    PolicySecurityMode SecurityMode { get; }

    /// <summary>
    /// If true, the compliance layer must enforce FIPS-approved algorithms only and fail-closed
    /// if no FIPS-approved candidate exists. See [FIPS-000].
    /// </summary>
    bool FipsRequired { get; }

    /// <summary>
    /// Minimum security strength (in bits) required per algorithm category.
    /// The selection engine rejects any algorithm below this threshold.
    /// </summary>
    ImmutableDictionary<AlgorithmCategory, SecurityStrength> MinimumStrengthByCategory { get; }

    /// <summary>
    /// Provider allowlist. In production profiles, an empty allowlist causes fail-closed behavior
    /// (no provider is trusted). See [ARC-010] trust boundary rules.
    /// </summary>
    ImmutableArray<ProviderId> ProviderAllowlist { get; }

    /// <summary>
    /// Optional provider pinning at the category level (e.g., all KEMs must be served by provider X).
    /// Overridden by <see cref="PinnedProviderByAlgorithm"/> if both are specified.
    /// </summary>
    ImmutableDictionary<AlgorithmCategory, ProviderId> PinnedProviderByCategory { get; }

    /// <summary>
    /// Optional provider pinning at the algorithm level (e.g., ML-KEM-768 must be served by provider Y).
    /// Takes precedence over <see cref="PinnedProviderByCategory"/>.
    /// </summary>
    ImmutableDictionary<AlgorithmId, ProviderId> PinnedProviderByAlgorithm { get; }

    /// <summary>
    /// SHA-384 hash of canonicalized policy bytes (signature covers canonical bytes).
    /// Used for binding, audit, and integrity verification across trust boundaries.
    /// </summary>
    ReadOnlyMemory<byte> PolicyHash { get; }
}