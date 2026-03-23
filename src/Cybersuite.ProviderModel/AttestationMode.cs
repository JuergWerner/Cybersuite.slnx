namespace Cybersuite.ProviderModel;

/// <summary>
/// Provider-declared attestation mode transported in the compliance envelope.
/// Wave 1 transports the declaration but does not yet enforce attestation evidence.
/// </summary>
public enum AttestationMode
{
    /// <summary>Provider does not support or require attestation evidence.</summary>
    None = 0,

    /// <summary>Provider supports attestation but does not require it from the host.</summary>
    Optional = 1,

    /// <summary>Provider requires attestation evidence to be exchanged during handshake.</summary>
    Required = 2
}
