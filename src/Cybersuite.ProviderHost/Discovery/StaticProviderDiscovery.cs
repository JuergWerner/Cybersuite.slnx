using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.ProviderHost.Discovery;

/// <summary>
/// Simple <see cref="IProviderDiscovery"/> implementation that yields a
/// pre-configured, immutable list of <see cref="ProviderPackage"/> instances.
/// Useful for testing, fixed deployments, and in-process provider setups.
/// </summary>
public sealed class StaticProviderDiscovery : IProviderDiscovery
{
    private readonly ImmutableArray<ProviderPackage> _packages;

    public StaticProviderDiscovery(IEnumerable<ProviderPackage> packages)
    {
        _packages = ImmutableArray.CreateRange(packages);
    }

    public async IAsyncEnumerable<ProviderPackage> DiscoverAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var p in _packages)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return p;
            await Task.Yield();
        }
    }
}