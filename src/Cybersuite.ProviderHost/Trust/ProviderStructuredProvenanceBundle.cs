using System;
using System.Text.Json;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Structured provider provenance bundle transported via <see cref="ProviderManifest.SignatureBundleBase64"/>.
/// Wave 4 uses this to make provenance data operationally relevant before full CI/SBOM signing lands in Wave 5.
/// </summary>
public sealed record ProviderStructuredProvenanceBundle(
    string ProviderId,
    string EntrypointSha256Hex,
    ProviderSecurityClass SecurityClass,
    RequiredBoundaryClass BoundaryClass,
    string? ModuleName,
    string? ModuleVersion,
    string SignerFingerprint,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset? ExpiresAtUtc)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    public string ToBase64()
    {
        byte[] utf8 = JsonSerializer.SerializeToUtf8Bytes(this, JsonOptions);
        return Convert.ToBase64String(utf8);
    }

    public static bool TryParseBase64(string? base64, out ProviderStructuredProvenanceBundle? bundle, out string? failureReason)
    {
        bundle = null;
        failureReason = null;

        if (string.IsNullOrWhiteSpace(base64))
        {
            failureReason = "Structured provenance bundle is missing.";
            return false;
        }

        try
        {
            byte[] utf8 = Convert.FromBase64String(base64);
            bundle = JsonSerializer.Deserialize<ProviderStructuredProvenanceBundle>(utf8, JsonOptions);
            if (bundle is null)
            {
                failureReason = "Structured provenance bundle could not be deserialized.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.ProviderId))
            {
                failureReason = "Structured provenance bundle provider id is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.EntrypointSha256Hex))
            {
                failureReason = "Structured provenance bundle entrypoint hash is missing.";
                bundle = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(bundle.SignerFingerprint))
            {
                failureReason = "Structured provenance bundle signer fingerprint is missing.";
                bundle = null;
                return false;
            }

            return true;
        }
        catch (FormatException)
        {
            failureReason = "Structured provenance bundle is not valid Base64.";
            return false;
        }
        catch (JsonException)
        {
            failureReason = "Structured provenance bundle is not valid JSON.";
            return false;
        }
    }

    public static string NormalizeFingerprint(string value)
        => (value ?? string.Empty).Replace(" ", string.Empty, StringComparison.Ordinal).Trim().ToUpperInvariant();
}
