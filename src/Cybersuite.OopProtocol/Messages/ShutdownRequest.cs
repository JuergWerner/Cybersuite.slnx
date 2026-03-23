using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP request to shut down the provider connection. When <see cref="Graceful"/>
/// is <c>true</c> the provider drains in-flight requests before stopping;
/// when <c>false</c> it terminates immediately.
/// </summary>
public sealed class ShutdownRequest
{
    public OopRequestHeader Header { get; }
    public bool Graceful { get; }

    public ShutdownRequest(OopRequestHeader header, bool graceful)
    {
        Header = header;
        Graceful = graceful;
    }
}