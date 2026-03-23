using System;
using System.Text.Json;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Structured source-release bundle transported via <see cref="ProviderManifest.ReleaseBundleBase64"/>.
/// Wave 5 uses this to make release-repository, release-channel, and SBOM/release-manifest digest claims
/// operationally relevant outside Dev without pretending to be a complete external CI/SLSA pipeline.
/// </summary>
public sealed record ProviderStructuredReleaseBundle(
    string ProviderId,
    string EntrypointSha256Hex,
    ProviderSecurityClass SecurityClass,
    RequiredBoundaryClass BoundaryClass,
    string ReleaseVersion,
    string ReleaseChannel,
    string SourceRepository,
    string ReleaseManifestSha256Hex,
    string SbomSha256Hex,
    string SignerFingerprint,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset? ExpiresAtUtc)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    public byte[] ToUtf8Bytes()
        => JsonSerializer.SerializeToUtf8Bytes(this, JsonOptions);

    public string ToBase64()
        => Convert.ToBase64String(ToUtf8Bytes());

    public static bool TryParseBase64(string? base64, out ProviderStructuredReleaseBundle? bundle, out string? failureReason)
    {
        bundle = null;
        failureReason = null;

        if (string.IsNullOrWhiteSpace(base64))
        {
            failureReason = "Structured release bundle is missing.";
            return false;
        }

        try
        {
            byte[] utf8 = Convert.FromBase64String(base64);
            bundle = JsonSerializer.Deserialize<ProviderStructuredReleaseBundle>(utf8, JsonOptions);
            if (bundle is null)
            {
                failureReason = "Structured release bundle could not be deserialized.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.ProviderId))
            {
                failureReason = "Structured release bundle provider id is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.EntrypointSha256Hex))
            {
                failureReason = "Structured release bundle entrypoint hash is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.ReleaseVersion))
            {
                failureReason = "Structured release bundle version is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.ReleaseChannel))
            {
                failureReason = "Structured release bundle channel is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.SourceRepository))
            {
                failureReason = "Structured release bundle source repository is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.ReleaseManifestSha256Hex))
            {
                failureReason = "Structured release bundle release-manifest digest is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.SbomSha256Hex))
            {
                failureReason = "Structured release bundle SBOM digest is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.SignerFingerprint))
            {
                failureReason = "Structured release bundle signer fingerprint is missing.";
                bundle = null;
                return false;
            }

            return true;
        }
        catch (FormatException)
        {
            failureReason = "Structured release bundle is not valid Base64.";
            return false;
        }
        catch (JsonException)
        {
            failureReason = "Structured release bundle is not valid JSON.";
            return false;
        }
    }

    public static string NormalizeFingerprint(string value)
        => ProviderStructuredProvenanceBundle.NormalizeFingerprint(value);

    public static string NormalizeRepository(string value)
    {
        string normalized = (value ?? string.Empty).Trim();
        while (normalized.EndsWith("/", StringComparison.Ordinal))
            normalized = normalized[..^1];

        return normalized;
    }
}
