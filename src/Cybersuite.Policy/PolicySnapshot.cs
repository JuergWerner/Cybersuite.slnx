using System.Collections.Immutable;
using Cybersuite.Abstractions;

namespace Cybersuite.Policy;

/// <summary>
/// Immutable, thread-safe policy snapshot implementing <see cref="IPolicy"/>.
/// Produced by <see cref="PolicyLoader"/> after JSON parsing, canonicalization, SHA-384 hashing,
/// optional signature verification, and anti-rollback sequence checks [ARC-400].
/// Carries the policy hash (SHA-384 of canonical bytes) used for session binding across
/// the entire ProviderHost/OOP handshake chain. Once created, a PolicySnapshot is frozen
/// and can be shared safely across threads and provider sessions.
/// </summary>
public sealed class PolicySnapshot : IPolicy
{
    public string SchemaVersion { get; }
    public long Sequence { get; }
    public string? TenantId { get; }
    public PolicySecurityMode SecurityMode { get; }
    public bool FipsRequired { get; }

    public ImmutableDictionary<AlgorithmCategory, SecurityStrength> MinimumStrengthByCategory { get; }
    public ImmutableArray<ProviderId> ProviderAllowlist { get; }
    public ImmutableDictionary<AlgorithmCategory, ProviderId> PinnedProviderByCategory { get; }
    public ImmutableDictionary<AlgorithmId, ProviderId> PinnedProviderByAlgorithm { get; }

    public ReadOnlyMemory<byte> PolicyHash { get; }

    internal PolicySnapshot(
        string schemaVersion,
        long sequence,
        string? tenantId,
        PolicySecurityMode securityMode,
        bool fipsRequired,
        ImmutableDictionary<AlgorithmCategory, SecurityStrength> minimumStrengthByCategory,
        ImmutableArray<ProviderId> providerAllowlist,
        ImmutableDictionary<AlgorithmCategory, ProviderId> pinnedProviderByCategory,
        ImmutableDictionary<AlgorithmId, ProviderId> pinnedProviderByAlgorithm,
        ReadOnlyMemory<byte> policyHash)
    {
        SchemaVersion = schemaVersion;
        Sequence = sequence;
        TenantId = tenantId;
        SecurityMode = securityMode;
        FipsRequired = fipsRequired;
        MinimumStrengthByCategory = minimumStrengthByCategory;
        ProviderAllowlist = providerAllowlist;
        PinnedProviderByCategory = pinnedProviderByCategory;
        PinnedProviderByAlgorithm = pinnedProviderByAlgorithm;
        PolicyHash = policyHash;
    }
}