using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP acknowledgement confirming that the provider has accepted
/// the shutdown request and is (or has) terminating.
/// </summary>
public sealed class ShutdownResponse
{
    public OopResponseHeader Header { get; }

    public ShutdownResponse(OopResponseHeader header)
    {
        Header = header;
    }
}