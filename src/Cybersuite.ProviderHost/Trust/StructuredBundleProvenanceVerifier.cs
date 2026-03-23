using System;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Fail-closed verifier for the Wave 4 structured provenance bundle.
/// This intentionally validates bundle structure, identity, boundary claims, signer allowlisting,
/// and lifetime without pretending to be the final Wave 5 CI/SBOM provenance system.
/// </summary>
public sealed class StructuredBundleProvenanceVerifier : IProviderProvenanceVerifier
{
    public static StructuredBundleProvenanceVerifier Default { get; } = new();

    public ValueTask<ProviderProvenanceVerificationResult> VerifyAsync(
        ProviderPackage package,
        ProviderHostOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(options);

        bool nonDev = options.ExecutionProfile != ExecutionProfile.Dev;
        bool bundleRequired = nonDev && options.RequireStructuredProvenanceBundleInNonDev;

        if (string.IsNullOrWhiteSpace(package.Manifest.SignatureBundleBase64))
        {
            return ValueTask.FromResult(
                bundleRequired
                    ? ProviderProvenanceVerificationResult.Rejected(
                        ProviderProvenanceStatus.Missing,
                        "Structured provenance bundle is required outside Dev.")
                    : ProviderProvenanceVerificationResult.Accepted(
                        ProviderProvenanceStatus.NotEvaluated,
                        "Structured provenance bundle not required in the current profile."));
        }

        if (!ProviderStructuredProvenanceBundle.TryParseBase64(
                package.Manifest.SignatureBundleBase64,
                out ProviderStructuredProvenanceBundle? bundle,
                out string? parseFailure))
        {
            return ValueTask.FromResult(
                ProviderProvenanceVerificationResult.Rejected(
                    ProviderProvenanceStatus.Rejected,
                    parseFailure ?? "Structured provenance bundle parsing failed."));
        }

        if (!string.Equals(bundle!.ProviderId, package.Manifest.ProviderId.Value, StringComparison.Ordinal))
        {
            return ValueTask.FromResult(
                ProviderProvenanceVerificationResult.Rejected(
                    ProviderProvenanceStatus.Rejected,
                    "Structured provenance bundle provider id mismatch.",
                    ProviderStructuredProvenanceBundle.NormalizeFingerprint(bundle.SignerFingerprint)));
        }

        if (!string.Equals(bundle.EntrypointSha256Hex, package.Manifest.EntrypointSha256Hex, StringComparison.OrdinalIgnoreCase))
        {
            return ValueTask.FromResult(
                ProviderProvenanceVerificationResult.Rejected(
                    ProviderProvenanceStatus.Rejected,
                    "Structured provenance bundle entrypoint hash mismatch.",
                    ProviderStructuredProvenanceBundle.NormalizeFingerprint(bundle.SignerFingerprint)));
        }

        if (bundle.SecurityClass != package.Manifest.ComplianceEnvelope.SecurityClass ||
            bundle.BoundaryClass != package.Manifest.ComplianceEnvelope.BoundaryClass)
        {
            return ValueTask.FromResult(
                ProviderProvenanceVerificationResult.Rejected(
                    ProviderProvenanceStatus.Rejected,
                    "Structured provenance bundle boundary claim mismatch.",
                    ProviderStructuredProvenanceBundle.NormalizeFingerprint(bundle.SignerFingerprint)));
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (bundle.ExpiresAtUtc is DateTimeOffset expiresAtUtc && now > expiresAtUtc)
        {
            return ValueTask.FromResult(
                ProviderProvenanceVerificationResult.Rejected(
                    ProviderProvenanceStatus.Rejected,
                    "Structured provenance bundle expired.",
                    ProviderStructuredProvenanceBundle.NormalizeFingerprint(bundle.SignerFingerprint)));
        }

        string normalizedFingerprint = ProviderStructuredProvenanceBundle.NormalizeFingerprint(bundle.SignerFingerprint);
        if (nonDev && options.AllowedProvenanceSignerFingerprints.Count > 0 &&
            !options.AllowedProvenanceSignerFingerprints.Contains(normalizedFingerprint))
        {
            return ValueTask.FromResult(
                ProviderProvenanceVerificationResult.Rejected(
                    ProviderProvenanceStatus.Rejected,
                    "Structured provenance bundle signer fingerprint not allowlisted.",
                    normalizedFingerprint));
        }

        return ValueTask.FromResult(
            ProviderProvenanceVerificationResult.Accepted(
                ProviderProvenanceStatus.StructuredValidated,
                "Structured provenance bundle accepted.",
                normalizedFingerprint));
    }
}
