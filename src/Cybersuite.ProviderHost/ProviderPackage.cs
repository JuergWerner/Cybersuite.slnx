using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Represents the on-disk artefact of a provider: its manifest metadata,
/// the package root directory, and the entrypoint binary path.
/// Discovered by <see cref="Discovery.IProviderDiscovery"/> and evaluated
/// by <see cref="Trust.IProviderTrustEvaluator"/> before launch.
/// </summary>
public sealed record ProviderPackage
{
    public required ProviderManifest Manifest { get; init; }
    public required string PackageRoot { get; init; }
    public required string EntrypointPath { get; init; }
}

/// <summary>
/// Declarative metadata embedded in or alongside a provider artefact.
/// Includes provider identity, isolation mode, integrity pins, and the canonical
/// compliance envelope that must match the provider's runtime hello message.
/// </summary>
public sealed record ProviderManifest
{
    public required ProviderId ProviderId { get; init; }
    public required string Version { get; init; }
    public required string Vendor { get; init; }

    public required ProviderIsolationMode IsolationMode { get; init; }
    public bool IsExperimental { get; init; }

    /// <summary>
    /// Legacy compatibility flag retained for additive evolution. Wave 1 expects this to match
    /// <see cref="ComplianceEnvelope.DeclaredValidatedBoundary"/>.
    /// </summary>
    public bool FipsBoundaryDeclared { get; init; }

    /// <summary>
    /// Canonical provider compliance declaration used for boundary and module admission.
    /// </summary>
    public ProviderComplianceEnvelope ComplianceEnvelope { get; init; } = ProviderComplianceEnvelope.ReferenceInProcessDefault;

    /// <summary>
    /// Hex-encoded SHA-256 hash of the entrypoint binary or assembly as packaged.
    /// This is an integrity pin, not a secret.
    /// </summary>
    public string? EntrypointSha256Hex { get; init; }

    /// <summary>
    /// Signed provenance or signature bundle. Wave 1 transports the field but does not yet
    /// require non-placeholder provenance verification everywhere.
    /// </summary>
    public string? SignatureBundleBase64 { get; init; }

    /// <summary>
    /// Structured source-release bundle carrying release-repository/channel and digest claims.
    /// Wave 5 uses this for packaging/release truth outside Dev.
    /// </summary>
    public string? ReleaseBundleBase64 { get; init; }
}
