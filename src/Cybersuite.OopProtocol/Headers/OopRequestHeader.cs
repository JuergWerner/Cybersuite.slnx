using System;

namespace Cybersuite.OopProtocol.Headers;

/// <summary>
/// Per-message request header for the Out-of-Process Protocol (OPP).
/// Every request carries channel-binding and replay-prevention primitives that the provider
/// MUST validate before processing the payload [OOP-010].
///
/// <list type="bullet">
///   <item><see cref="ChannelBindingSha384"/> — SHA-384 binding derived from the handshake transcript; prevents cross-session replay.</item>
///   <item><see cref="MessageCounter"/> — strictly monotonic counter (starting at 1); prevents in-session replay and message reordering.</item>
///   <item><see cref="RequestId"/> — unique 128-bit correlation token for request/response matching.</item>
/// </list>
/// </summary>
public sealed class OopRequestHeader
{
    /// <summary>OPP protocol version for this message.</summary>
    public ProtocolVersion Version { get; }

    /// <summary>Discriminator identifying the request payload type.</summary>
    public OopMessageType MessageType { get; }

    /// <summary>Unique 128-bit correlation ID for request/response matching.</summary>
    public Handle128 RequestId { get; }

    /// <summary>Strictly monotonic message counter (starts at 1). Provider rejects out-of-order or repeated counters.</summary>
    public ulong MessageCounter { get; }

    /// <summary>
    /// SHA-384 channel binding derived from handshake transcript.
    /// </summary>
    public ReadOnlyMemory<byte> ChannelBindingSha384 { get; }

    public OopRequestHeader(
        ProtocolVersion version,
        OopMessageType messageType,
        Handle128 requestId,
        ulong messageCounter,
        ReadOnlySpan<byte> channelBindingSha384)
    {
        if (messageCounter == 0)
            throw new ArgumentOutOfRangeException(nameof(messageCounter), "MessageCounter must be >= 1.");

        if (channelBindingSha384.Length != OopConstants.Sha384SizeBytes)
            throw new ArgumentException("ChannelBindingSha384 must be 48 bytes (SHA-384).", nameof(channelBindingSha384));

        Version = version;
        MessageType = messageType;
        RequestId = requestId;
        MessageCounter = messageCounter;

        // Defensive copy for immutability
        var cb = new byte[OopConstants.Sha384SizeBytes];
        channelBindingSha384.CopyTo(cb);
        ChannelBindingSha384 = cb;
    }

    public byte[] ToCanonicalBytes() => OopWireFormat.EncodeRequestHeader(this);
}