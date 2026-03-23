using System.Threading;
using System.Threading.Tasks;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Evaluates whether a discovered <see cref="ProviderPackage"/> is trusted
/// before the host launches it. Checks may include allowlist membership,
/// entrypoint integrity (SHA-256 pin), provenance-bundle validation, and policy constraints.
/// </summary>
public interface IProviderTrustEvaluator
{
    ValueTask<ProviderTrustDecision> EvaluateAsync(ProviderPackage package, ProviderHostOptions options, CancellationToken cancellationToken);
}

/// <summary>
/// Result of a trust evaluation: whether the provider is trusted,
/// why the decision was made, and which provenance state became active.
/// </summary>
public readonly record struct ProviderTrustDecision(
    bool IsTrusted,
    string Reason,
    ProviderProvenanceStatus ProvenanceStatus = ProviderProvenanceStatus.NotEvaluated,
    string? ProvenanceSignerFingerprint = null,
    ProviderReleaseStatus ReleaseStatus = ProviderReleaseStatus.NotEvaluated,
    string? ReleaseRepositoryUri = null,
    string? ReleaseChannel = null,
    string? ReleaseSignerFingerprint = null,
    string? ReleaseManifestSha256Hex = null,
    string? ReleaseSbomSha256Hex = null);
