using System;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Fail-closed verifier for the Wave 5 structured release bundle.
/// It validates repository/channel allowlisting and the presence/binding of release-manifest and SBOM digests,
/// without pretending that the bundle alone is a complete external software-supply-chain attestation.
/// </summary>
public sealed class StructuredReleaseBundleVerifier : IProviderReleaseVerifier
{
    public static StructuredReleaseBundleVerifier Default { get; } = new();

    public ValueTask<ProviderReleaseVerificationResult> VerifyAsync(
        ProviderPackage package,
        ProviderHostOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(options);

        bool nonDev = options.ExecutionProfile != ExecutionProfile.Dev;
        bool bundleRequired = nonDev && options.RequireStructuredReleaseBundleInNonDev;

        if (string.IsNullOrWhiteSpace(package.Manifest.ReleaseBundleBase64))
        {
            return ValueTask.FromResult(
                bundleRequired
                    ? ProviderReleaseVerificationResult.Rejected(
                        ProviderReleaseStatus.Missing,
                        "Structured release bundle is required outside Dev.")
                    : ProviderReleaseVerificationResult.Accepted(
                        ProviderReleaseStatus.NotEvaluated,
                        "Structured release bundle not required in the current profile."));
        }

        if (!ProviderStructuredReleaseBundle.TryParseBase64(
                package.Manifest.ReleaseBundleBase64,
                out ProviderStructuredReleaseBundle? bundle,
                out string? parseFailure))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    parseFailure ?? "Structured release bundle parsing failed."));
        }

        string normalizedRepo = ProviderStructuredReleaseBundle.NormalizeRepository(bundle!.SourceRepository);
        string normalizedFingerprint = ProviderStructuredReleaseBundle.NormalizeFingerprint(bundle.SignerFingerprint);

        if (!string.Equals(bundle.ProviderId, package.Manifest.ProviderId.Value, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle provider id mismatch.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (!string.Equals(bundle.EntrypointSha256Hex, package.Manifest.EntrypointSha256Hex, StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle entrypoint hash mismatch.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (bundle.SecurityClass != package.Manifest.ComplianceEnvelope.SecurityClass ||
            bundle.BoundaryClass != package.Manifest.ComplianceEnvelope.BoundaryClass)
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle boundary claim mismatch.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (!string.Equals(bundle.ReleaseVersion, package.Manifest.Version, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle version mismatch.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (bundle.ExpiresAtUtc is DateTimeOffset expiresAtUtc && now > expiresAtUtc)
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle expired.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (nonDev && options.AllowedReleaseRepositoryUris.Count > 0 &&
            !options.AllowedReleaseRepositoryUris.Contains(normalizedRepo))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle source repository not allowlisted.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (nonDev && options.AllowedReleaseChannels.Count > 0 &&
            !options.AllowedReleaseChannels.Contains(bundle.ReleaseChannel))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle release channel not allowlisted.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (nonDev && options.AllowedReleaseSignerFingerprints.Count > 0 &&
            !options.AllowedReleaseSignerFingerprints.Contains(normalizedFingerprint))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle signer fingerprint not allowlisted.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (nonDev && options.RequireReleaseManifestDigestInNonDev && !IsSha256Hex(bundle.ReleaseManifestSha256Hex))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle release-manifest digest is invalid.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        if (nonDev && options.RequireReleaseSbomDigestInNonDev && !IsSha256Hex(bundle.SbomSha256Hex))
        {
            return ValueTask.FromResult(
                ProviderReleaseVerificationResult.Rejected(
                    ProviderReleaseStatus.Rejected,
                    "Structured release bundle SBOM digest is invalid.",
                    normalizedRepo,
                    bundle.ReleaseChannel,
                    normalizedFingerprint,
                    bundle.ReleaseManifestSha256Hex,
                    bundle.SbomSha256Hex));
        }

        return ValueTask.FromResult(
            ProviderReleaseVerificationResult.Accepted(
                ProviderReleaseStatus.StructuredValidated,
                "Structured release bundle accepted.",
                normalizedRepo,
                bundle.ReleaseChannel,
                normalizedFingerprint,
                bundle.ReleaseManifestSha256Hex,
                bundle.SbomSha256Hex));
    }

    private static bool IsSha256Hex(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64)
            return false;

        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            bool hex = (c >= '0' && c <= '9') ||
                       (c >= 'a' && c <= 'f') ||
                       (c >= 'A' && c <= 'F');
            if (!hex)
                return false;
        }

        return true;
    }
}
