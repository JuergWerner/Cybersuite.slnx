using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Concrete decoder for the canonical capability JSON defined by CapabilitySnapshot.GetCanonicalBytes().
/// This replaces the previous "not implemented" placeholder while keeping the same file path.
///
/// Security properties:
/// - immutable output only
/// - claimed SHA-384 validated in fixed-time
/// - canonical bytes re-derived and matched to input (fail-closed)
/// - no secret material involved
/// </summary>
public class CapabilitySnapshotJsonDecoder : ICapabilitySnapshotDecoder
{
    public CapabilitySnapshot Decode(
        ProviderIdentity identity,
        ReadOnlySpan<byte> capabilityCanonicalBytes,
        ReadOnlySpan<byte> claimedCapabilityHashSha384)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (capabilityCanonicalBytes.IsEmpty)
            throw new InvalidOperationException("CapabilityCanonicalBytes must not be empty.");

        if (claimedCapabilityHashSha384.Length != 48)
            throw new InvalidOperationException("CapabilityHashSha384 must be 48 bytes (SHA-384).");

        using var doc = JsonDocument.Parse(
            capabilityCanonicalBytes.ToArray(),
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            });

        JsonElement root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Capability root must be a JSON object.");

        string providerIdText = GetRequiredString(root, "providerId");
        string versionText = GetRequiredString(root, "version");
        string buildHashText = GetRequiredString(root, "buildHash");
        string signatureFingerprintText = GetRequiredString(root, "signatureFingerprint");

        if (!string.Equals(providerIdText, identity.ProviderId.Value, StringComparison.Ordinal))
            throw new InvalidOperationException("Capability providerId does not match ProviderIdentity.");

        if (!string.Equals(versionText, identity.Version, StringComparison.Ordinal))
            throw new InvalidOperationException("Capability version does not match ProviderIdentity.");

        if (!string.Equals(buildHashText, identity.BuildHash, StringComparison.Ordinal))
            throw new InvalidOperationException("Capability buildHash does not match ProviderIdentity.");

        string identityFingerprint = identity.SignatureFingerprint ?? string.Empty;
        if (!string.Equals(signatureFingerprintText, identityFingerprint, StringComparison.Ordinal))
            throw new InvalidOperationException("Capability signatureFingerprint does not match ProviderIdentity.");

        if (!root.TryGetProperty("algorithms", out JsonElement algorithmsEl) || algorithmsEl.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("Capability payload must contain algorithms array.");

        var algorithms = new List<AlgorithmDescriptor>();

        foreach (JsonElement alg in algorithmsEl.EnumerateArray())
        {
            if (alg.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException("Algorithm entry must be an object.");

            string algorithmIdText = GetRequiredString(alg, "algorithmId");
            string categoryText = GetRequiredString(alg, "category");
            string securityModeText = GetRequiredString(alg, "securityMode");
            bool isFipsApproved = GetRequiredBool(alg, "isFipsApproved");
            int strengthBits = GetRequiredInt32(alg, "strengthBits");
            int hybridClassicalBits = GetRequiredInt32(alg, "hybridClassicalBits");
            int hybridPostQuantumBits = GetRequiredInt32(alg, "hybridPostQuantumBits");

            string parameterSetIdText = GetOptionalString(alg, "parameterSetId") ?? string.Empty;
            string operationalMaturityText = GetOptionalString(alg, "operationalMaturity") ?? "Stable";
            string encodingProfileText = GetOptionalString(alg, "encodingProfile") ?? "ProviderNative";

            AlgorithmCategory category = ParseCategory(categoryText);
            AlgorithmSecurityMode securityMode = ParseSecurityMode(securityModeText);
            var strength = new SecurityStrength(strengthBits);
            AlgorithmOperationalMaturity maturity = ParseOperationalMaturity(operationalMaturityText);
            AlgorithmEncodingProfile encodingProfile = ParseEncodingProfile(encodingProfileText);

            HybridSecurityStrength? hybridStrength = null;
            if (securityMode == AlgorithmSecurityMode.Hybrid)
            {
                if (hybridClassicalBits <= 0 || hybridPostQuantumBits <= 0)
                    throw new InvalidOperationException("Hybrid algorithm requires positive hybrid bits.");

                hybridStrength = new HybridSecurityStrength(
                    new SecurityStrength(hybridClassicalBits),
                    new SecurityStrength(hybridPostQuantumBits));
            }
            else
            {
                if (hybridClassicalBits != 0 || hybridPostQuantumBits != 0)
                    throw new InvalidOperationException("Non-hybrid algorithm must have zero hybrid bits.");
            }

            AlgorithmParameterSetId? parameterSetId =
                string.IsNullOrWhiteSpace(parameterSetIdText) ? null : new AlgorithmParameterSetId(parameterSetIdText);

            algorithms.Add(new AlgorithmDescriptor(
                id: new AlgorithmId(algorithmIdText),
                provider: identity.ProviderId,
                category: category,
                securityMode: securityMode,
                strength: strength,
                isFipsApproved: isFipsApproved,
                hybridStrength: hybridStrength,
                parameterSetId: parameterSetId,
                operationalMaturity: maturity,
                encodingProfile: encodingProfile));
        }

        var artifactProfiles = ImmutableDictionary.CreateBuilder<AlgorithmId, CapabilityArtifactProfile>();

        if (root.TryGetProperty("artifactProfiles", out JsonElement artifactProfilesEl))
        {
            if (artifactProfilesEl.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException("artifactProfiles must be an object.");

            foreach (var property in artifactProfilesEl.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.Object)
                    throw new InvalidOperationException("artifactProfiles entries must be objects.");

                JsonElement ap = property.Value;

                artifactProfiles[new AlgorithmId(property.Name)] = new CapabilityArtifactProfile(
                    publicKeyBytes: GetRequiredInt32(ap, "publicKeyBytes"),
                    privateKeyBytes: GetRequiredInt32(ap, "privateKeyBytes"),
                    ciphertextBytes: GetRequiredInt32(ap, "ciphertextBytes"),
                    signatureBytes: GetRequiredInt32(ap, "signatureBytes"),
                    sharedSecretBytes: GetRequiredInt32(ap, "sharedSecretBytes"),
                    symmetricKeyBytes: GetRequiredInt32(ap, "symmetricKeyBytes"),
                    nonceBytes: GetRequiredInt32(ap, "nonceBytes"),
                    tagBytes: GetRequiredInt32(ap, "tagBytes"),
                    publicKeyEncodingProfile: ParseEncodingProfile(GetRequiredString(ap, "publicKeyEncodingProfile")),
                    privateKeyEncodingProfile: ParseEncodingProfile(GetRequiredString(ap, "privateKeyEncodingProfile")));
            }
        }

        CapabilitySnapshot snapshot = CapabilitySnapshot.Create(
            identity,
            ImmutableArray.CreateRange(algorithms),
            artifactProfiles.ToImmutable());

        if (snapshot.CapabilityHashSha384.Length != 48)
            throw new InvalidOperationException("Decoded capability hash length invalid.");

        bool hashMatches = CryptographicOperations.FixedTimeEquals(
            snapshot.CapabilityHashSha384.Span,
            claimedCapabilityHashSha384);

        if (!hashMatches)
            throw new InvalidOperationException("Claimed capability hash does not match decoded snapshot.");

        byte[] recomputedCanonical = snapshot.GetCanonicalBytes();
        bool sameCanonical =
            recomputedCanonical.Length == capabilityCanonicalBytes.Length &&
            CryptographicOperations.FixedTimeEquals(recomputedCanonical, capabilityCanonicalBytes);

        CryptographicOperations.ZeroMemory(recomputedCanonical);

        if (!sameCanonical)
            throw new InvalidOperationException("Capability canonical bytes are not in canonical form.");

        return snapshot;
    }

    private static string GetRequiredString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out JsonElement p) || p.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException($"Missing or invalid string field '{name}'.");

        return (p.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
    }

    private static string? GetOptionalString(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out JsonElement p))
            return null;

        if (p.ValueKind == JsonValueKind.Null)
            return null;

        if (p.ValueKind != JsonValueKind.String)
            throw new InvalidOperationException($"Invalid optional string field '{name}'.");

        return (p.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
    }

    private static bool GetRequiredBool(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out JsonElement p))
            throw new InvalidOperationException($"Missing boolean field '{name}'.");

        return p.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new InvalidOperationException($"Invalid boolean field '{name}'.")
        };
    }

    private static int GetRequiredInt32(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out JsonElement p) || p.ValueKind != JsonValueKind.Number || !p.TryGetInt32(out int value))
            throw new InvalidOperationException($"Missing or invalid integer field '{name}'.");

        return value;
    }

    private static AlgorithmCategory ParseCategory(string value)
        => value switch
        {
            "KeyEncapsulation" => AlgorithmCategory.KeyEncapsulation,
            "KeyExchange" => AlgorithmCategory.KeyExchange,
            "Signature" => AlgorithmCategory.Signature,
            "SymmetricAead" => AlgorithmCategory.SymmetricAead,
            "KeyDerivation" => AlgorithmCategory.KeyDerivation,
            "Hash" => AlgorithmCategory.Hash,
            "Mac" => AlgorithmCategory.Mac,
            "Random" => AlgorithmCategory.Random,
            "Authentication" => AlgorithmCategory.Authentication,
            _ => throw new InvalidOperationException($"Unknown AlgorithmCategory '{value}'.")
        };

    private static AlgorithmSecurityMode ParseSecurityMode(string value)
        => value switch
        {
            "Classical" => AlgorithmSecurityMode.Classical,
            "Pqc" => AlgorithmSecurityMode.Pqc,
            "Hybrid" => AlgorithmSecurityMode.Hybrid,
            _ => throw new InvalidOperationException($"Unknown AlgorithmSecurityMode '{value}'.")
        };

    private static AlgorithmOperationalMaturity ParseOperationalMaturity(string value)
        => value switch
        {
            "Stable" => AlgorithmOperationalMaturity.Stable,
            "Experimental" => AlgorithmOperationalMaturity.Experimental,
            "Deprecated" => AlgorithmOperationalMaturity.Deprecated,
            _ => throw new InvalidOperationException($"Unknown AlgorithmOperationalMaturity '{value}'.")
        };

    private static AlgorithmEncodingProfile ParseEncodingProfile(string value)
        => value switch
        {
            "ProviderNative" => AlgorithmEncodingProfile.ProviderNative,
            "SubjectPublicKeyInfo" => AlgorithmEncodingProfile.SubjectPublicKeyInfo,
            "Pkcs8PrivateKey" => AlgorithmEncodingProfile.Pkcs8PrivateKey,
            "RawPublicKey" => AlgorithmEncodingProfile.RawPublicKey,
            "RawPrivateKey" => AlgorithmEncodingProfile.RawPrivateKey,
            "SeedOnlyPrivateKey" => AlgorithmEncodingProfile.SeedOnlyPrivateKey,
            "ExpandedPrivateKey" => AlgorithmEncodingProfile.ExpandedPrivateKey,
            _ => throw new InvalidOperationException($"Unknown AlgorithmEncodingProfile '{value}'.")
        };
}

[Obsolete("Use CapabilitySnapshotJsonDecoder instead.")]
public sealed class NotImplementedCapabilitySnapshotDecoder : CapabilitySnapshotJsonDecoder
{
}