using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderModel;

namespace Cybersuite.Runtime;

public static class ProviderRegistryFlattener
{
    /// <summary>
    /// Flattens trusted provider capabilities into a single immutable descriptor set.
    /// No LINQ in hot path; deterministic selection is guaranteed by the Selection layer.
    /// </summary>
    public static ImmutableArray<AlgorithmDescriptor> FlattenTrusted(ProviderRegistrySnapshot snapshot)
    {
        var builder = ImmutableArray.CreateBuilder<AlgorithmDescriptor>();

        foreach (var kv in snapshot.Providers)
        {
            var record = kv.Value;

            if (record.Metadata.TrustState != ProviderTrustState.Trusted)
                continue;

            var capabilities = record.Capabilities.Algorithms;
            for (int i = 0; i < capabilities.Length; i++)
            {
                builder.Add(capabilities[i]);
            }
        }

        return builder.ToImmutable();
    }
}