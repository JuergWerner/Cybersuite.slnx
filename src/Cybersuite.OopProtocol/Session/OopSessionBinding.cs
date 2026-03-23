using System;
using System.Security.Cryptography;
using Cybersuite.ProviderModel;
using Cybersuite.OopProtocol.Handshake;

namespace Cybersuite.OopProtocol.Session;

/// <summary>
/// Immutable session binding computed from the OPP handshake (ClientHello + ProviderHello).
/// Captures the cryptographic transcript hash and derived channel-binding value that are
/// used to validate every subsequent request/response header for the session lifetime.
///
/// This object is the trust anchor for the OPP session: it binds the protocol version,
/// provider identity, policy hash, and capability hash into a single immutable token
/// that cannot be altered without detection.
/// </summary>
public sealed class OopSessionBinding
{
    /// <summary>Negotiated OPP protocol version for this session.</summary>
    public ProtocolVersion ProtocolVersion { get; }

    /// <summary>Authenticated provider identity extracted from the ProviderHello handshake message.</summary>
    public ProviderIdentity ProviderIdentity { get; }

    /// <summary>SHA-384 policy hash from the ClientHello, binding this session to a specific policy snapshot.</summary>
    public ReadOnlyMemory<byte> PolicyHashSha384 { get; }

    /// <summary>SHA-384 capability hash from the ProviderHello, binding this session to a specific capability snapshot.</summary>
    public ReadOnlyMemory<byte> CapabilityHashSha384 { get; }

    /// <summary>SHA-384 transcript hash computed over both handshake messages. Input to the channel binding derivation.</summary>
    public ReadOnlyMemory<byte> TranscriptHashSha384 { get; }

    /// <summary>SHA-384 channel-binding value derived from the transcript hash. Verified in every request/response header.</summary>
    public ReadOnlyMemory<byte> ChannelBindingSha384 { get; }

    private OopSessionBinding(
        ProtocolVersion protocolVersion,
        ProviderIdentity providerIdentity,
        ReadOnlyMemory<byte> policyHashSha384,
        ReadOnlyMemory<byte> capabilityHashSha384,
        ReadOnlyMemory<byte> transcriptHashSha384,
        ReadOnlyMemory<byte> channelBindingSha384)
    {
        ProtocolVersion = protocolVersion;
        ProviderIdentity = providerIdentity;

        PolicyHashSha384 = policyHashSha384;
        CapabilityHashSha384 = capabilityHashSha384;
        TranscriptHashSha384 = transcriptHashSha384;
        ChannelBindingSha384 = channelBindingSha384;
    }

    public static OopSessionBinding Create(ClientHello clientHello, ProviderHello providerHello)
    {
        if (clientHello is null) throw new ArgumentNullException(nameof(clientHello));
        if (providerHello is null) throw new ArgumentNullException(nameof(providerHello));

        // Anti-downgrade: protocol version must match exactly in v1 design (tight).
        if (!clientHello.Version.Equals(providerHello.Version))
            throw new OopProtocolException("ProtocolVersion mismatch between ClientHello and ProviderHello.");

        byte[] transcript = HandshakeTranscript.ComputeTranscriptHashSha384(clientHello, providerHello);
        byte[] channelBinding = HandshakeTranscript.ComputeChannelBindingSha384(transcript);

        // Defensive copies (immutable)
        var ph = clientHello.PolicyHashSha384.ToArray();
        var ch = providerHello.CapabilityHashSha384.ToArray();

        return new OopSessionBinding(
            protocolVersion: clientHello.Version,
            providerIdentity: providerHello.Identity,
            policyHashSha384: ph,
            capabilityHashSha384: ch,
            transcriptHashSha384: transcript,
            channelBindingSha384: channelBinding);
    }

    public bool ValidateChannelBinding(ReadOnlySpan<byte> channelBindingSha384)
        => OopFixedTime.FixedTimeEqualsSha384(ChannelBindingSha384.Span, channelBindingSha384);

    public bool ValidatePolicyHash(ReadOnlySpan<byte> policyHashSha384)
        => OopFixedTime.FixedTimeEqualsSha384(PolicyHashSha384.Span, policyHashSha384);

    public bool ValidateCapabilityHash(ReadOnlySpan<byte> capabilityHashSha384)
        => OopFixedTime.FixedTimeEqualsSha384(CapabilityHashSha384.Span, capabilityHashSha384);

    /// <summary>
    /// Convenience for fixed-time compare with expected provider build hash (string compare is not constant-time,
    /// but build hash is not a secret; do NOT use for raw key material).
    /// </summary>
    public bool ProviderBuildHashEquals(string expectedBuildHash)
        => string.Equals(ProviderIdentity.BuildHash, expectedBuildHash, StringComparison.Ordinal);
}