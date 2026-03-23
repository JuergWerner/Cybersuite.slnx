using System;
using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// Provider returns canonical bytes of capability snapshot plus hash (SHA-384).
/// Capability bytes MUST NOT include secrets.
/// </summary>
public sealed class CapabilityResponse
{
    public OopResponseHeader Header { get; }
    public ReadOnlyMemory<byte> CapabilityCanonicalBytes { get; }
    public ReadOnlyMemory<byte> CapabilityHashSha384 { get; }

    public CapabilityResponse(
        OopResponseHeader header,
        ReadOnlySpan<byte> capabilityCanonicalBytes,
        ReadOnlySpan<byte> capabilityHashSha384)
    {
        if (capabilityHashSha384.Length != OopConstants.Sha384SizeBytes)
            throw new ArgumentException("CapabilityHashSha384 must be 48 bytes.", nameof(capabilityHashSha384));

        Header = header;

        CapabilityCanonicalBytes = capabilityCanonicalBytes.ToArray();

        var h = new byte[OopConstants.Sha384SizeBytes];
        capabilityHashSha384.CopyTo(h);
        CapabilityHashSha384 = h;
    }
}