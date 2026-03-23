using System.Collections.Generic;
using System.Threading;

namespace Cybersuite.ProviderHost.Discovery;

/// <summary>
/// Asynchronously discovers available <see cref="ProviderPackage"/> artefacts
/// (e.g. scanning a directory, reading a configuration, or querying a registry).
/// The host iterates the results and subjects each package to trust evaluation.
/// </summary>
public interface IProviderDiscovery
{
    IAsyncEnumerable<ProviderPackage> DiscoverAsync(CancellationToken cancellationToken);
}