using Cybersuite.Abstractions;
using Cybersuite.ProviderHost.Launch;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Immutable start-transaction snapshot for a single provider package.
/// Used for diagnostics, failure journaling, and deterministic retry analysis.
/// </summary>
public sealed record ProviderStartTransaction(
    ProviderPackage Package,
    ProviderLaunchContext LaunchContext,
    ProviderLifecycleState State,
    string? ReasonCode,
    Exception? Exception,
    DateTimeOffset StartedAt,
    DateTimeOffset? FinishedAt)
{
    public ProviderId ProviderId => Package.Manifest.ProviderId;

    public bool IsTerminal =>
        State is ProviderLifecycleState.TrustRejected
        or ProviderLifecycleState.Ready
        or ProviderLifecycleState.Faulted
        or ProviderLifecycleState.RolledBack;
}
