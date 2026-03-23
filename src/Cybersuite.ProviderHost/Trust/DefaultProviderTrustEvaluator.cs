using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Default trust evaluator implementing a multi-gate pipeline:
/// 1) profile-aware allowlist enforcement,
/// 2) provider id allowlist check,
/// 3) SHA-256 entrypoint integrity verification,
/// 4) structured provenance bundle validation.
/// Any failed gate returns an untrusted decision with a diagnostic reason.
/// </summary>
public sealed class DefaultProviderTrustEvaluator : IProviderTrustEvaluator
{
    private readonly ILogger<DefaultProviderTrustEvaluator> _logger;

    public DefaultProviderTrustEvaluator(ILogger<DefaultProviderTrustEvaluator>? logger = null)
    {
        _logger = logger ?? NullLogger<DefaultProviderTrustEvaluator>.Instance;
    }

    public async ValueTask<ProviderTrustDecision> EvaluateAsync(
        ProviderPackage package,
        ProviderHostOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (options.ExecutionProfile == ExecutionProfile.Prod &&
            options.RequireNonEmptyAllowlistInProd &&
            options.ProviderIdAllowlist.IsEmpty)
        {
            _logger.LogWarning("Trust rejected {ProviderId}: empty allowlist in Prod", package.Manifest.ProviderId.Value);
            return new ProviderTrustDecision(false, "Prod profile requires non-empty provider allowlist.");
        }

        if (!options.ProviderIdAllowlist.IsEmpty &&
            !options.ProviderIdAllowlist.Contains(package.Manifest.ProviderId))
        {
            _logger.LogWarning("Trust rejected {ProviderId}: not in allowlist", package.Manifest.ProviderId.Value);
            return new ProviderTrustDecision(false, "ProviderId not allowlisted.");
        }

        if (options.ExpectedEntrypointSha256ByProvider.TryGetValue(package.Manifest.ProviderId, out var expectedSha256))
        {
            if (expectedSha256.IsDefaultOrEmpty || expectedSha256.Length != 32)
                return new ProviderTrustDecision(false, "Expected SHA-256 hash must be 32 bytes.");

            byte[] measured = await ComputeSha256Async(package.EntrypointPath, cancellationToken).ConfigureAwait(false);
            bool ok = CryptographicOperations.FixedTimeEquals(measured, expectedSha256.AsSpan());
            CryptographicOperations.ZeroMemory(measured);

            if (!ok)
            {
                _logger.LogWarning("Trust rejected {ProviderId}: entrypoint hash mismatch", package.Manifest.ProviderId.Value);
                return new ProviderTrustDecision(false, "Entrypoint hash mismatch.");
            }
        }
        else if (!string.IsNullOrWhiteSpace(package.Manifest.EntrypointSha256Hex))
        {
            if (!TryParseHex(package.Manifest.EntrypointSha256Hex!, out var expectedFromManifest) || expectedFromManifest.Length != 32)
                return new ProviderTrustDecision(false, "Manifest EntrypointSha256Hex invalid.");

            byte[] measured = await ComputeSha256Async(package.EntrypointPath, cancellationToken).ConfigureAwait(false);
            bool ok = CryptographicOperations.FixedTimeEquals(measured, expectedFromManifest);

            CryptographicOperations.ZeroMemory(measured);
            CryptographicOperations.ZeroMemory(expectedFromManifest);

            if (!ok && options.ExecutionProfile == ExecutionProfile.Prod)
                return new ProviderTrustDecision(false, "Entrypoint hash mismatch (manifest-declared).");
        }

        ProviderReleaseVerificationResult release = await options.ReleaseVerifier
            .VerifyAsync(package, options, cancellationToken)
            .ConfigureAwait(false);

        if (!release.IsAccepted)
        {
            _logger.LogWarning(
                "Trust rejected {ProviderId}: release verification failed ({Reason})",
                package.Manifest.ProviderId.Value,
                release.Reason);

            return new ProviderTrustDecision(
                false,
                release.Reason,
                ReleaseStatus: release.Status,
                ReleaseRepositoryUri: release.RepositoryUri,
                ReleaseChannel: release.ReleaseChannel,
                ReleaseSignerFingerprint: release.SignerFingerprint,
                ReleaseManifestSha256Hex: release.ReleaseManifestSha256Hex,
                ReleaseSbomSha256Hex: release.SbomSha256Hex);
        }

        ProviderProvenanceVerificationResult provenance = await options.ProvenanceVerifier
            .VerifyAsync(package, options, cancellationToken)
            .ConfigureAwait(false);

        if (!provenance.IsAccepted)
        {
            _logger.LogWarning(
                "Trust rejected {ProviderId}: provenance verification failed ({Reason})",
                package.Manifest.ProviderId.Value,
                provenance.Reason);

            return new ProviderTrustDecision(
                false,
                provenance.Reason,
                provenance.Status,
                provenance.SignerFingerprint);
        }

        _logger.LogDebug(
            "Trust accepted {ProviderId} with provenance status {ProvenanceStatus}",
            package.Manifest.ProviderId.Value,
            provenance.Status);

        return new ProviderTrustDecision(
            true,
            "Trusted by allowlist/hash/release/provenance policy.",
            provenance.Status,
            provenance.SignerFingerprint,
            release.Status,
            release.RepositoryUri,
            release.ReleaseChannel,
            release.SignerFingerprint,
            release.ReleaseManifestSha256Hex,
            release.SbomSha256Hex);
    }

    private static async Task<byte[]> ComputeSha256Async(string path, CancellationToken ct)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha = SHA256.Create();
        return await sha.ComputeHashAsync(stream, ct).ConfigureAwait(false);
    }

    private static bool TryParseHex(string hex, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();

        hex = hex.Trim();
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];

        if (hex.Length == 0 || (hex.Length % 2 != 0))
            return false;

        var buffer = new byte[hex.Length / 2];
        for (int i = 0; i < buffer.Length; i++)
        {
            int hi = ParseNibble(hex[2 * i]);
            int lo = ParseNibble(hex[2 * i + 1]);
            if (hi < 0 || lo < 0)
            {
                CryptographicOperations.ZeroMemory(buffer);
                return false;
            }

            buffer[i] = (byte)((hi << 4) | lo);
        }

        bytes = buffer;
        return true;

        static int ParseNibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }
}
