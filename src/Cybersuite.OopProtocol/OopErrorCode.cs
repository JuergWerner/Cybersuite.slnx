namespace Cybersuite.OopProtocol;

/// <summary>
/// Structured error codes sent in <see cref="OopError"/> responses when a provider
/// cannot fulfil a request. Codes are grouped by domain:
/// 10-19 = security/binding, 20-29 = protocol/message,
/// 30-39 = capability/selection, 40-49 = lifecycle, 99 = generic internal.
/// </summary>
public enum OopErrorCode : ushort
{
    Unknown = 0,

    // Security / binding
    InvalidChannelBinding = 10,
    ReplayDetected = 11,
    CounterOutOfOrder = 12,

    // Protocol / message
    UnsupportedProtocolVersion = 20,
    InvalidMessage = 21,

    // Capability / selection related
    CapabilityUnavailable = 30,

    // Lifecycle
    ShuttingDown = 40,

    // Generic
    InternalError = 99
}