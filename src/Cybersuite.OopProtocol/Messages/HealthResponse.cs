using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP response to a health probe. <see cref="IsHealthy"/> is <c>true</c>
/// when the provider is fully operational and ready to accept requests.
/// </summary>
public sealed class HealthResponse
{
    public OopResponseHeader Header { get; }
    public bool IsHealthy { get; }

    public HealthResponse(OopResponseHeader header, bool isHealthy)
    {
        Header = header;
        IsHealthy = isHealthy;
    }
}