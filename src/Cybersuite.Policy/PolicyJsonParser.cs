using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Cybersuite.Abstractions;

namespace Cybersuite.Policy;

internal static class PolicyJsonParser
{
    internal sealed record Model(
        string SchemaVersion,
        long Sequence,
        string? TenantId,
        PolicySecurityMode SecurityMode,
        bool FipsRequired,
        ImmutableDictionary<AlgorithmCategory, SecurityStrength> MinStrengthByCategory,
        ImmutableArray<ProviderId> ProviderAllowlist,
        ImmutableDictionary<AlgorithmCategory, ProviderId> PinnedProviderByCategory,
        ImmutableDictionary<AlgorithmId, ProviderId> PinnedProviderByAlgorithm,
        PolicySignatureEnvelope? Signature);

    public static Model Parse(ReadOnlySpan<byte> policyUtf8)
    {
        var docOptions = new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64
        };

        using var doc = JsonDocument.Parse(policyUtf8.ToArray(), docOptions);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException("Policy root must be a JSON object.");

        string schemaVersion = GetRequiredString(root, "schemaVersion");
        long sequence = GetRequiredInt64(root, "sequence");
        string? tenantId = GetOptionalString(root, "tenantId");

        var securityMode = ParseSecurityMode(GetRequiredString(root, "securityMode"));
        bool fipsRequired = GetOptionalBool(root, "fipsRequired") ?? false;

        var minStrength = ParseMinStrength(root);
        var allowlist = ParseProviderAllowlist(root);
        var pinByCategory = ParsePinnedByCategory(root);
        var pinByAlgorithm = ParsePinnedByAlgorithm(root);

        var signature = ParseSignatureEnvelope(root);

        return new Model(
            schemaVersion,
            sequence,
            tenantId,
            securityMode,
            fipsRequired,
            minStrength,
            allowlist,
            pinByCategory,
            pinByAlgorithm,
            signature);
    }

    private static string GetRequiredString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.String)
            throw new PolicyValidationException($"Missing/invalid required string: {name}");

        return (p.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
    }

    private static string? GetOptionalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var p))
            return null;

        if (p.ValueKind == JsonValueKind.Null)
            return null;

        if (p.ValueKind != JsonValueKind.String)
            throw new PolicyValidationException($"Invalid optional string: {name}");

        return (p.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
    }

    private static long GetRequiredInt64(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var p) || p.ValueKind != JsonValueKind.Number || !p.TryGetInt64(out var v))
            throw new PolicyValidationException($"Missing/invalid required integer: {name}");

        return v;
    }

    private static bool? GetOptionalBool(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var p))
            return null;

        return p.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => throw new PolicyValidationException($"Invalid optional boolean: {name}")
        };
    }

    private static PolicySecurityMode ParseSecurityMode(string s)
    {
        return s switch
        {
            "Classical" => PolicySecurityMode.Classical,
            "Pqc" => PolicySecurityMode.Pqc,
            "Hybrid" => PolicySecurityMode.Hybrid,
            _ => throw new PolicyValidationException("Invalid securityMode. Expected: Classical|Pqc|Hybrid")
        };
    }

    private static ImmutableDictionary<AlgorithmCategory, SecurityStrength> ParseMinStrength(JsonElement root)
    {
        if (!root.TryGetProperty("minimumStrengthByCategory", out var obj) || obj.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException("Missing/invalid minimumStrengthByCategory object.");

        var builder = ImmutableDictionary.CreateBuilder<AlgorithmCategory, SecurityStrength>();

        foreach (var p in obj.EnumerateObject())
        {
            var cat = ParseCategory(p.Name);
            if (p.Value.ValueKind != JsonValueKind.Number || !p.Value.TryGetInt32(out int bits))
                throw new PolicyValidationException("minimumStrengthByCategory values must be integers.");

            builder[cat] = new SecurityStrength(bits);
        }

        if (builder.Count == 0)
            throw new PolicyValidationException("minimumStrengthByCategory must not be empty.");

        return builder.ToImmutable();
    }

    private static ImmutableArray<ProviderId> ParseProviderAllowlist(JsonElement root)
    {
        if (!root.TryGetProperty("providerAllowlist", out var arr))
            return ImmutableArray<ProviderId>.Empty;

        if (arr.ValueKind == JsonValueKind.Null)
            return ImmutableArray<ProviderId>.Empty;

        if (arr.ValueKind != JsonValueKind.Array)
            throw new PolicyValidationException("providerAllowlist must be an array of strings.");

        var list = new List<ProviderId>();
        foreach (var e in arr.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.String)
                throw new PolicyValidationException("providerAllowlist entries must be strings.");

            var s = (e.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
            if (s.Length == 0) continue;
            list.Add(new ProviderId(s));
        }

        return list.ToImmutableArray();
    }

    private static ImmutableDictionary<AlgorithmCategory, ProviderId> ParsePinnedByCategory(JsonElement root)
    {
        if (!root.TryGetProperty("pinnedProviderByCategory", out var obj))
            return ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty;

        if (obj.ValueKind == JsonValueKind.Null)
            return ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty;

        if (obj.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException("pinnedProviderByCategory must be an object.");

        var builder = ImmutableDictionary.CreateBuilder<AlgorithmCategory, ProviderId>();
        foreach (var p in obj.EnumerateObject())
        {
            var cat = ParseCategory(p.Name);
            if (p.Value.ValueKind != JsonValueKind.String)
                throw new PolicyValidationException("pinnedProviderByCategory values must be strings.");

            var prov = (p.Value.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
            if (prov.Length == 0)
                throw new PolicyValidationException("pinnedProviderByCategory providerId must be non-empty.");

            builder[cat] = new ProviderId(prov);
        }

        return builder.ToImmutable();
    }

    private static ImmutableDictionary<AlgorithmId, ProviderId> ParsePinnedByAlgorithm(JsonElement root)
    {
        if (!root.TryGetProperty("pinnedProviderByAlgorithm", out var obj))
            return ImmutableDictionary<AlgorithmId, ProviderId>.Empty;

        if (obj.ValueKind == JsonValueKind.Null)
            return ImmutableDictionary<AlgorithmId, ProviderId>.Empty;

        if (obj.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException("pinnedProviderByAlgorithm must be an object.");

        var builder = ImmutableDictionary.CreateBuilder<AlgorithmId, ProviderId>();
        foreach (var p in obj.EnumerateObject())
        {
            var algId = p.Name.Normalize(NormalizationForm.FormC);
            if (algId.Length == 0)
                throw new PolicyValidationException("AlgorithmId in pinnedProviderByAlgorithm must be non-empty.");

            if (p.Value.ValueKind != JsonValueKind.String)
                throw new PolicyValidationException("pinnedProviderByAlgorithm values must be strings.");

            var prov = (p.Value.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
            if (prov.Length == 0)
                throw new PolicyValidationException("ProviderId in pinnedProviderByAlgorithm must be non-empty.");

            builder[new AlgorithmId(algId)] = new ProviderId(prov);
        }

        return builder.ToImmutable();
    }

    private static AlgorithmCategory ParseCategory(string name)
    {
        // Policy keys use enum names (Ordinal, case-sensitive)
        return name switch
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
            _ => throw new PolicyValidationException($"Unknown AlgorithmCategory: {name}")
        };
    }

    private static PolicySignatureEnvelope? ParseSignatureEnvelope(JsonElement root)
    {
        if (!root.TryGetProperty("signature", out var sig))
            return null;

        if (sig.ValueKind == JsonValueKind.Null)
            return null;

        if (sig.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException("signature must be an object.");

        string algStr = GetRequiredString(sig, "algorithm");
        var algorithm = algStr switch
        {
            "RSA-PSS-SHA384" => PolicySignatureAlgorithm.RsaPssSha384,
            "ECDSA-P384-SHA384" => PolicySignatureAlgorithm.EcdsaP384Sha384,
            _ => throw new PolicyValidationException("signature.algorithm unsupported (use RSA-PSS-SHA384 or ECDSA-P384-SHA384).")
        };

        string sigB64 = GetRequiredString(sig, "valueBase64");
        byte[] sigBytes;
        try { sigBytes = Convert.FromBase64String(sigB64); }
        catch { throw new PolicyValidationException("signature.valueBase64 invalid base64."); }

        string certB64 = GetRequiredString(sig, "signerCertDerBase64");
        byte[] certDer;
        try { certDer = Convert.FromBase64String(certB64); }
        catch { throw new PolicyValidationException("signature.signerCertDerBase64 invalid base64."); }

        ImmutableArray<ReadOnlyMemory<byte>> intermediates = ImmutableArray<ReadOnlyMemory<byte>>.Empty;
        if (sig.TryGetProperty("chainDerBase64", out var chainEl))
        {
            if (chainEl.ValueKind == JsonValueKind.Array)
            {
                var list = new List<ReadOnlyMemory<byte>>();
                foreach (var e in chainEl.EnumerateArray())
                {
                    if (e.ValueKind != JsonValueKind.String)
                        throw new PolicyValidationException("signature.chainDerBase64 must be array of base64 strings.");

                    var b64 = (e.GetString() ?? string.Empty).Normalize(NormalizationForm.FormC);
                    try { list.Add(Convert.FromBase64String(b64)); }
                    catch { throw new PolicyValidationException("signature.chainDerBase64 contains invalid base64."); }
                }
                intermediates = list.ToImmutableArray();
            }
            else if (chainEl.ValueKind != JsonValueKind.Null)
            {
                throw new PolicyValidationException("signature.chainDerBase64 must be array or null.");
            }
        }

        return new PolicySignatureEnvelope(
            algorithm,
            sigBytes,
            certDer,
            intermediates);
    }
}