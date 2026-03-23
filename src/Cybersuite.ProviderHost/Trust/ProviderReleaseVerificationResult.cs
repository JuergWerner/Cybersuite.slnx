using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

public readonly record struct ProviderReleaseVerificationResult(
    bool IsAccepted,
    ProviderReleaseStatus Status,
    string Reason,
    string? RepositoryUri,
    string? ReleaseChannel,
    string? SignerFingerprint,
    string? ReleaseManifestSha256Hex,
    string? SbomSha256Hex)
{
    public static ProviderReleaseVerificationResult Accepted(
        ProviderReleaseStatus status,
        string reason,
        string? repositoryUri = null,
        string? releaseChannel = null,
        string? signerFingerprint = null,
        string? releaseManifestSha256Hex = null,
        string? sbomSha256Hex = null)
        => new(true, status, reason, repositoryUri, releaseChannel, signerFingerprint, releaseManifestSha256Hex, sbomSha256Hex);

    public static ProviderReleaseVerificationResult Rejected(
        ProviderReleaseStatus status,
        string reason,
        string? repositoryUri = null,
        string? releaseChannel = null,
        string? signerFingerprint = null,
        string? releaseManifestSha256Hex = null,
        string? sbomSha256Hex = null)
        => new(false, status, reason, repositoryUri, releaseChannel, signerFingerprint, releaseManifestSha256Hex, sbomSha256Hex);
}
