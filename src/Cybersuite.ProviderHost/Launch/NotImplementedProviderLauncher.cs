using System;
using System.Collections.Immutable;
using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.ProviderHost.Launch;

/// <summary>
/// Composite launcher that delegates to registered concrete launch handlers.
/// The handler decision is based on the real, host-derived <see cref="ProviderLaunchContext"/>,
/// never on a hardcoded development profile.
/// </summary>
public class CompositeProviderLauncher : IProviderLauncher
{
    private readonly ImmutableArray<IProviderLaunchHandler> _handlers;

    public CompositeProviderLauncher(params IProviderLaunchHandler[] handlers)
    {
        _handlers = ImmutableArray.CreateRange(handlers ?? Array.Empty<IProviderLaunchHandler>());
    }

    public ValueTask<IProviderConnection> LaunchAsync(
        ProviderPackage package,
        ProviderLaunchContext launchContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(launchContext);
        launchContext.Validate();

        for (int i = 0; i < _handlers.Length; i++)
        {
            var handler = _handlers[i];
            if (handler.CanLaunch(package, launchContext))
            {
                return handler.LaunchAsync(package, launchContext, cancellationToken);
            }
        }

        throw new NotSupportedException($"No launch handler registered for provider '{package.Manifest.ProviderId.Value}' under the current launch context.");
    }
}

/// <summary>
/// Backward-compatible wrapper for older composition code.
/// </summary>
[Obsolete("Use CompositeProviderLauncher instead.")]
public sealed class NotImplementedProviderLauncher : CompositeProviderLauncher
{
    public NotImplementedProviderLauncher(params IProviderLaunchHandler[] handlers)
        : base(handlers)
    {
    }
}
