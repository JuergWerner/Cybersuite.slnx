using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP liveness probe. The host sends this periodically or on demand
/// to verify the provider process is still responsive.
/// </summary>
public sealed class HealthRequest
{
    public OopRequestHeader Header { get; }

    public HealthRequest(OopRequestHeader header)
    {
        Header = header;
    }
}