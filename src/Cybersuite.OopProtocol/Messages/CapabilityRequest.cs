using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP request asking the provider to report its full capability set
/// (supported algorithms, security modes, strength levels).
/// Issued after the handshake to populate the provider registry.
/// </summary>
public sealed class CapabilityRequest
{
    public OopRequestHeader Header { get; }

    public CapabilityRequest(OopRequestHeader header)
    {
        Header = header;
    }
}