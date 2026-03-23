using System;
using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderHost.Trust;

namespace Cybersuite.ProviderHost;

public sealed record ProviderHostOptions
{
    public required ExecutionProfile ExecutionProfile { get; init; }

    /// <summary>
    /// Fail-closed production default: in Prod profile an empty allowlist rejects all providers.
    /// </summary>
    public bool RequireNonEmptyAllowlistInProd { get; init; } = true;

    /// <summary>
    /// Provider IDs that may be started/loaded by this host.
    /// Empty allowlists are allowed in Dev/Staging, but not recommended.
    /// </summary>
    public ImmutableHashSet<ProviderId> ProviderIdAllowlist { get; init; } =
        ImmutableHashSet<ProviderId>.Empty;

    /// <summary>
    /// Optional build-hash pinning (SHA-256). If set for a provider, the measured entrypoint hash must match.
    /// </summary>
    public ImmutableDictionary<ProviderId, ImmutableArray<byte>> ExpectedEntrypointSha256ByProvider { get; init; } =
        ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty;


    /// <summary>
    /// Outside Dev, require a structured source-release bundle on the package manifest.
    /// Wave 5 uses this to make release-repository/channel and SBOM/release-manifest digests operationally relevant.
    /// </summary>
    public bool RequireStructuredReleaseBundleInNonDev { get; init; } = true;

    /// <summary>
    /// Optional allowlist of normalized source repository URIs accepted for provider releases.
    /// </summary>
    public ImmutableHashSet<string> AllowedReleaseRepositoryUris { get; init; } =
        ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Optional allowlist of release channels accepted outside Dev (for example: prod-source, staging-source).
    /// </summary>
    public ImmutableHashSet<string> AllowedReleaseChannels { get; init; } =
        ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Optional allowlist of structured release signer fingerprints (normalized uppercase, no spaces).
    /// </summary>
    public ImmutableHashSet<string> AllowedReleaseSignerFingerprints { get; init; } =
        ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Outside Dev, the release bundle must carry a valid SHA-256 digest for the release manifest.
    /// </summary>
    public bool RequireReleaseManifestDigestInNonDev { get; init; } = true;

    /// <summary>
    /// Outside Dev, the release bundle must carry a valid SHA-256 digest for the SBOM.
    /// </summary>
    public bool RequireReleaseSbomDigestInNonDev { get; init; } = true;

    /// <summary>
    /// Verifier used for the structured source-release bundle transported by the package manifest.
    /// </summary>
    public IProviderReleaseVerifier ReleaseVerifier { get; init; } = StructuredReleaseBundleVerifier.Default;


    /// <summary>
    /// Outside Dev, require a structured provenance bundle on the package manifest.
    /// Wave 4 makes provenance data operationally relevant without overclaiming full CI/SBOM provenance.
    /// </summary>
    public bool RequireStructuredProvenanceBundleInNonDev { get; init; } = true;

    /// <summary>
    /// Optional allowlist of provenance signer fingerprints (normalized uppercase, no spaces).
    /// When populated outside Dev, provenance bundles must bind to one of these fingerprints.
    /// </summary>
    public ImmutableHashSet<string> AllowedProvenanceSignerFingerprints { get; init; } =
        ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Verifier used for the structured provider provenance bundle transported by the package manifest.
    /// </summary>
    public IProviderProvenanceVerifier ProvenanceVerifier { get; init; } = StructuredBundleProvenanceVerifier.Default;

    /// <summary>
    /// When true, non-Dev profiles require attestation evidence whenever the provider declares an attestation mode.
    /// </summary>
    public bool RequireAttestationInNonDevWhenDeclared { get; init; } = true;

    /// <summary>
    /// Optional allowlist of exact SHA-256 hashes for attestation evidence per provider.
    /// </summary>
    public ImmutableDictionary<ProviderId, ImmutableArray<byte>> ExpectedAttestationEvidenceSha256ByProvider { get; init; } =
        ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty;

    /// <summary>
    /// Maximum accepted age of a structured self-attestation statement.
    /// </summary>
    public TimeSpan MaxStructuredAttestationAge { get; init; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Verifier used for provider handshake attestation evidence.
    /// </summary>
    public IProviderAttestationVerifier AttestationVerifier { get; init; } = StructuredAttestationVerifier.Default;

    /// <summary>
    /// Combined wall-clock budget for launch, handshake, and capability fetch.
    /// </summary>
    public TimeSpan ProviderStartupTimeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Max time allowed for graceful shutdown before best-effort disposal continues.
    /// </summary>
    public TimeSpan ProviderShutdownTimeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Whether provider launch handlers may enable network access for child processes or transports.
    /// </summary>
    public bool EnableNetworkAccess { get; init; } = false;

    /// <summary>
    /// Transport limits (e.g., gRPC message size). Wave 2 derives launch-time budgets from these values.
    /// Prefer streaming/chunking for very large payloads.
    /// </summary>
    public OopTransportLimits TransportLimits { get; init; } = OopTransportLimits.Default;
}

public sealed record OopTransportLimits
{
    /// <summary>
    /// Max inbound message bytes. Stage 6 should prefer streaming/chunking for large payloads.
    /// </summary>
    public int? MaxReceiveMessageSizeBytes { get; init; }

    /// <summary>Max outbound message bytes.</summary>
    public int? MaxSendMessageSizeBytes { get; init; }

    public static OopTransportLimits Default { get; } = new();
}
