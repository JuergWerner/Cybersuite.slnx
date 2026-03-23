using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Cybersuite.Abstractions;

namespace Cybersuite.Policy;

/// <summary>
/// Opinionated policy defaults for common local development workflows.
/// Wave 5 sets the default template to Development PQM so the shipped sample profile
/// prefers the Dev/reference BouncyCastle path with post-quantum asymmetric algorithms.
/// </summary>
public static class PolicyDefaults
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    public static PolicySnapshot CreateDevelopmentPqm(
        string? tenantId = "Development",
        ProviderId? providerId = null,
        long sequence = 1,
        bool fipsRequired = false)
    {
        ProviderId effectiveProviderId = providerId ?? new ProviderId("BouncyCastle");

        var minimumStrength = ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Empty
            .Add(AlgorithmCategory.KeyEncapsulation, new SecurityStrength(192))
            .Add(AlgorithmCategory.Signature, new SecurityStrength(192))
            .Add(AlgorithmCategory.SymmetricAead, new SecurityStrength(256))
            .Add(AlgorithmCategory.KeyDerivation, new SecurityStrength(192));

        ImmutableArray<ProviderId> allowlist = ImmutableArray.Create(effectiveProviderId);
        var pinnedByAlgorithm = ImmutableDictionary<AlgorithmId, ProviderId>.Empty
            .Add(new AlgorithmId("ML-KEM-768"), effectiveProviderId)
            .Add(new AlgorithmId("ML-DSA-65"), effectiveProviderId);

        byte[] canonical = CreateDevelopmentPqmJsonTemplate(tenantId, effectiveProviderId, sequence);
        byte[] policyHash = SHA384.HashData(canonical);

        return new PolicySnapshot(
            schemaVersion: "1.0",
            sequence: sequence,
            tenantId: tenantId,
            securityMode: PolicySecurityMode.Pqc,
            fipsRequired: fipsRequired,
            minimumStrengthByCategory: minimumStrength,
            providerAllowlist: allowlist,
            pinnedProviderByCategory: ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty,
            pinnedProviderByAlgorithm: pinnedByAlgorithm,
            policyHash: policyHash);
    }

    public static byte[] CreateDevelopmentPqmJsonTemplate(
        string? tenantId = "Development",
        ProviderId? providerId = null,
        long sequence = 1)
    {
        ProviderId effectiveProviderId = providerId ?? new ProviderId("BouncyCastle");

        var model = new
        {
            schemaVersion = "1.0",
            sequence,
            tenantId = tenantId ?? "Development",
            securityMode = "Pqc",
            fipsRequired = false,
            minimumStrengthByCategory = new Dictionary<string, int>
            {
                ["KeyEncapsulation"] = 192,
                ["Signature"] = 192,
                ["SymmetricAead"] = 256,
                ["KeyDerivation"] = 192
            },
            providerAllowlist = new[]
            {
                effectiveProviderId.Value
            },
            pinnedProviderByCategory = new { },
            pinnedProviderByAlgorithm = new Dictionary<string, string>
            {
                ["ML-KEM-768"] = effectiveProviderId.Value,
                ["ML-DSA-65"] = effectiveProviderId.Value
            },
            signature = (object?)null
        };

        return JsonSerializer.SerializeToUtf8Bytes(model, JsonOptions);
    }
}
