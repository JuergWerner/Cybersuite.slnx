using System;

namespace Cybersuite.OopProtocol.Headers;

/// <summary>
/// Per-message response header for the Out-of-Process Protocol (OPP).
/// Mirrors the request’s channel binding for verification and carries the correlation ID
/// plus success/error status. Validation: success responses must not carry an error;
/// failure responses must carry an error (fail-closed).
/// </summary>
public sealed class OopResponseHeader
{
    /// <summary>OPP protocol version for this message.</summary>
    public ProtocolVersion Version { get; }

    /// <summary>Discriminator identifying the response payload type.</summary>
    public OopMessageType MessageType { get; }

    /// <summary>Correlation ID matching the original request’s <see cref="OopRequestHeader.RequestId"/>.</summary>
    public Handle128 RequestId { get; }

    /// <summary>Monotonic message counter for response ordering.</summary>
    public ulong MessageCounter { get; }

    /// <summary>SHA-384 channel binding derived from the handshake transcript. Must match the request’s binding.</summary>
    public ReadOnlyMemory<byte> ChannelBindingSha384 { get; }

    /// <summary>Whether the request was processed successfully.</summary>
    public bool Success { get; }

    /// <summary>Structured error payload. Non-null iff <see cref="Success"/> is <c>false</c>.</summary>
    public OopError? Error { get; }

    public OopResponseHeader(
        ProtocolVersion version,
        OopMessageType messageType,
        Handle128 requestId,
        ulong messageCounter,
        ReadOnlySpan<byte> channelBindingSha384,
        bool success,
        OopError? error)
    {
        if (messageCounter == 0)
            throw new ArgumentOutOfRangeException(nameof(messageCounter), "MessageCounter must be >= 1.");

        if (channelBindingSha384.Length != OopConstants.Sha384SizeBytes)
            throw new ArgumentException("ChannelBindingSha384 must be 48 bytes (SHA-384).", nameof(channelBindingSha384));

        if (success && error is not null)
            throw new ArgumentException("Success responses must not carry an error.", nameof(error));

        if (!success && error is null)
            throw new ArgumentException("Failure responses must carry an error.", nameof(error));

        Version = version;
        MessageType = messageType;
        RequestId = requestId;
        MessageCounter = messageCounter;

        var cb = new byte[OopConstants.Sha384SizeBytes];
        channelBindingSha384.CopyTo(cb);
        ChannelBindingSha384 = cb;

        Success = success;
        Error = error;
    }

    public byte[] ToCanonicalBytes() => OopWireFormat.EncodeResponseHeader(this);
}