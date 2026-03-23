namespace Cybersuite.ProviderHost;

/// <summary>
/// Coarse-grained lifecycle state of the provider host itself.
/// This is separate from per-provider <see cref="ProviderLifecycleState"/>.
/// </summary>
public enum ProviderHostLifecycleState
{
    Stopped = 0,
    Starting = 1,
    Started = 2,
    Stopping = 3,
    Disposed = 4
}
