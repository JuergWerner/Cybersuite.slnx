using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.ProviderHost.Launch;

/// <summary>
/// Outer-ring launch handler for a concrete provider implementation.
/// Keeps ProviderHost free of concrete provider dependencies.
/// </summary>
public interface IProviderLaunchHandler
{
    bool CanLaunch(ProviderPackage package, ProviderLaunchContext launchContext);

    ValueTask<IProviderConnection> LaunchAsync(
        ProviderPackage package,
        ProviderLaunchContext launchContext,
        CancellationToken cancellationToken);
}
