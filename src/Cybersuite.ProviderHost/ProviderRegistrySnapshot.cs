using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Immutable, point-in-time snapshot of all registered providers and their capabilities.
/// Used by the selection and compliance layers to make algorithm-routing decisions without
/// locking the live registry.
/// </summary>
public sealed record ProviderRegistrySnapshot(
    ImmutableDictionary<ProviderId, ProviderRecord> Providers)
{
    public static ProviderRegistrySnapshot Empty { get; } =
        new(ImmutableDictionary<ProviderId, ProviderRecord>.Empty);
}

/// <summary>
/// Detailed record for a single provider in the registry: its metadata, capability snapshot,
/// transcript/channel-binding hashes, and the canonical compliance envelope observed during start.
/// </summary>
public sealed record ProviderRecord
{
    public required ProviderMetadata Metadata { get; init; }
    public required CapabilitySnapshot Capabilities { get; init; }

    /// <summary>
    /// Handshake transcript hash (SHA-384). Not secret, but security-critical; keep out of logs unless explicitly needed.
    /// </summary>
    public ImmutableArray<byte> TranscriptHashSha384 { get; init; } = ImmutableArray<byte>.Empty;

    /// <summary>
    /// Channel binding (SHA-384) derived from transcript hash.
    /// </summary>
    public ImmutableArray<byte> ChannelBindingSha384 { get; init; } = ImmutableArray<byte>.Empty;

    /// <summary>
    /// Canonical provider compliance envelope persisted for audit and admission.
    /// </summary>
    public ProviderComplianceEnvelope ComplianceEnvelope { get; init; } = ProviderComplianceEnvelope.ReferenceInProcessDefault;

    /// <summary>
    /// Result of structured provenance-bundle evaluation.
    /// </summary>
    public ProviderProvenanceStatus ProvenanceStatus { get; init; } = ProviderProvenanceStatus.NotEvaluated;

    public string? ProvenanceSignerFingerprint { get; init; }

    /// <summary>
    /// Result of structured source-release evaluation.
    /// </summary>
    public ProviderReleaseStatus ReleaseStatus { get; init; } = ProviderReleaseStatus.NotEvaluated;

    public string? ReleaseRepositoryUri { get; init; }

    public string? ReleaseChannel { get; init; }

    public string? ReleaseSignerFingerprint { get; init; }

    public string? ReleaseManifestSha256Hex { get; init; }

    public string? ReleaseSbomSha256Hex { get; init; }

    /// <summary>
    /// Result of handshake attestation evidence evaluation.
    /// </summary>
    public ProviderAttestationStatus AttestationStatus { get; init; } = ProviderAttestationStatus.NotRequired;

    public string? AttestationEvidenceSha256Hex { get; init; }

    public bool FipsBoundaryDeclared { get; init; }
}
