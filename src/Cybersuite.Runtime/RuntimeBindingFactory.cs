using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderHost;

namespace Cybersuite.Runtime;

public static class RuntimeBindingFactory
{
    public static ProviderSessionBinding Create(
        IPolicy policy,
        in SelectionContext context,
        RuntimeOptions options)
    {
        if (policy is null)
            throw new ArgumentNullException(nameof(policy));
        if (options is null)
            throw new ArgumentNullException(nameof(options));

        ReadOnlyMemory<byte> policyHash = policy.PolicyHash;
        if (policyHash.Length != 48)
            throw new ArgumentException("PolicyHash must be 48 bytes (SHA-384).", nameof(policy));

        EffectiveComplianceContext effective = CreateEffectiveComplianceContext(policy, context, options);

        ProviderId? expectedProviderId = TryGetSingleRequiredProviderId(effective.RequiredProviderIds);
        string? expectedBuildHash = TryGetSingleRequiredBuildHashHex(effective.RequiredBuildHashes, expectedProviderId);

        return new ProviderSessionBinding
        {
            PolicyHashSha384 = effective.PolicyHashSha384,
            ExecutionProfile = effective.Profile,
            FipsRequired = effective.EffectiveFipsRequired,
            ExperimentalAllowed = effective.ExperimentalAllowed,
            TenantId = effective.TenantId,
            ExpectedProviderId = expectedProviderId,
            ExpectedBuildHash = expectedBuildHash,
            EffectiveCompliance = effective
        };
    }

    public static EffectiveComplianceContext CreateEffectiveComplianceContext(
        IPolicy policy,
        in SelectionContext context,
        RuntimeOptions options)
    {
        bool effectiveFipsRequired = context.ForceFips ?? policy.FipsRequired;
        bool experimentalAllowed = options.IsExperimentalAllowed(context.Profile);

        return new EffectiveComplianceContext(
            profile: context.Profile,
            policyHashSha384: policy.PolicyHash.Span,
            tenantId: context.TenantId ?? policy.TenantId,
            policyFipsRequired: policy.FipsRequired,
            forceFips: context.ForceFips,
            experimentalAllowed: experimentalAllowed,
            requiredBoundaryClass: ComputeRequiredBoundaryClass(context.Profile, effectiveFipsRequired),
            requiredProviderIds: BuildRequiredProviderIds(policy),
            requiredBuildHashes: ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
            attestationRequirement: AttestationRequirement.None);
    }

    private static RequiredBoundaryClass ComputeRequiredBoundaryClass(
        ExecutionProfile profile,
        bool effectiveFipsRequired)
    {
        if (effectiveFipsRequired)
            return RequiredBoundaryClass.ValidatedBoundary;

        return profile switch
        {
            ExecutionProfile.Dev => RequiredBoundaryClass.None,
            ExecutionProfile.Staging => RequiredBoundaryClass.IsolatedProcess,
            ExecutionProfile.Prod => RequiredBoundaryClass.IsolatedProcess,
            _ => RequiredBoundaryClass.None
        };
    }

    private static ImmutableHashSet<ProviderId> BuildRequiredProviderIds(IPolicy policy)
    {
        var builder = ImmutableHashSet.CreateBuilder<ProviderId>();

        if (!policy.ProviderAllowlist.IsDefaultOrEmpty)
        {
            for (int i = 0; i < policy.ProviderAllowlist.Length; i++)
                builder.Add(policy.ProviderAllowlist[i]);
        }

        foreach (var kv in policy.PinnedProviderByCategory)
            builder.Add(kv.Value);

        foreach (var kv in policy.PinnedProviderByAlgorithm)
            builder.Add(kv.Value);

        return builder.ToImmutable();
    }

    private static ProviderId? TryGetSingleRequiredProviderId(ImmutableHashSet<ProviderId> providerIds)
    {
        if (providerIds.IsEmpty || providerIds.Count != 1)
            return null;

        foreach (ProviderId providerId in providerIds)
            return providerId;

        return null;
    }

    private static string? TryGetSingleRequiredBuildHashHex(
        ImmutableDictionary<ProviderId, ImmutableArray<byte>> buildHashes,
        ProviderId? expectedProviderId)
    {
        if (expectedProviderId is null)
            return null;

        if (!buildHashes.TryGetValue(expectedProviderId.Value, out ImmutableArray<byte> hash) ||
            hash.IsDefaultOrEmpty ||
            hash.Length != 32)
        {
            return null;
        }

        byte[] bytes = hash.ToArray();
        try
        {
            return Convert.ToHexString(bytes);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
