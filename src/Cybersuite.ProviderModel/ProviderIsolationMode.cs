namespace Cybersuite.ProviderModel;

/// <summary>
/// Defines the process-level isolation boundary between the Cybersuite core and a provider [ARC-302].
/// - <see cref="InProcess"/>: Provider runs in the same CLR process (fastest, lowest isolation; used for Dev/Interop).
/// - <see cref="OutOfProcess"/>: Provider runs in a separate OS process communicating via the OOP protocol (standard production mode).
/// - <see cref="HardwareBoundary"/>: Provider is backed by a hardware security module (HSM/TPM); highest isolation tier.
/// The ProviderHost uses this to select the appropriate launch handler and transport configuration.
/// </summary>
public enum ProviderIsolationMode
{
    /// <summary>Provider runs in the same CLR process as the core. Fastest, lowest isolation. Used for Dev/Reference paths.</summary>
    InProcess = 0,

    /// <summary>Provider runs in a separate OS process communicating via the OPP wire protocol. Standard production isolation mode.</summary>
    OutOfProcess = 1,

    /// <summary>Provider is backed by a hardware security module (HSM/TPM). Highest isolation tier. Future/planned.</summary>
    HardwareBoundary = 2
}