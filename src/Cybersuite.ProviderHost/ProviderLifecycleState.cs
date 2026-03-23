namespace Cybersuite.ProviderHost;

/// <summary>
/// Ordered lifecycle states for a single provider start transaction.
/// A provider is only admitted into the live registry once it reaches <see cref="Ready"/>.
/// </summary>
public enum ProviderLifecycleState
{
    Discovered = 0,
    TrustAccepted = 1,
    TrustRejected = 2,
    Launching = 3,
    Launched = 4,
    Handshaking = 5,
    CapabilityVerified = 6,
    Ready = 7,
    Faulted = 8,
    RolledBack = 9
}
