using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.ProviderHost.Launch;

/// <summary>
/// Launches a provider from its <see cref="ProviderPackage"/> artefact.
/// Implementations decide the concrete isolation: in-process assembly load,
/// out-of-process child, or container-based launch.
/// </summary>
public interface IProviderLauncher
{
    ValueTask<IProviderConnection> LaunchAsync(ProviderPackage package, ProviderLaunchContext launchContext, CancellationToken cancellationToken);
}
