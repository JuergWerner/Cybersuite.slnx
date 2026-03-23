using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Cybersuite.OopProtocol.Handshake;

/// <summary>
/// Computes the cryptographic transcript and channel-binding values for the OPP handshake.
/// The transcript hash (SHA-384) is computed over length-prefixed canonical serialisations
/// of <see cref="ClientHello"/> and <see cref="ProviderHello"/>, preceded by a domain-separation
/// label. The channel-binding value is a second SHA-384 hash over the transcript hash,
/// providing replay-protection for subsequent requests.
/// </summary>
public static class HandshakeTranscript
{
    public static byte[] ComputeTranscriptHashSha384(ClientHello clientHello, ProviderHello providerHello)
    {
        if (clientHello is null) throw new ArgumentNullException(nameof(clientHello));
        if (providerHello is null) throw new ArgumentNullException(nameof(providerHello));

        byte[] c = clientHello.ToCanonicalBytes();
        byte[] p = providerHello.ToCanonicalBytes();

        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);

        // Domain separation
        h.AppendData(OopConstants.TranscriptLabelV1);

        AppendLengthPrefixed(h, c);
        AppendLengthPrefixed(h, p);

        return h.GetHashAndReset();
    }

    public static byte[] ComputeChannelBindingSha384(ReadOnlySpan<byte> transcriptHashSha384)
    {
        if (transcriptHashSha384.Length != OopConstants.Sha384SizeBytes)
            throw new ArgumentException("Transcript hash must be 48 bytes.", nameof(transcriptHashSha384));

        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA384);
        h.AppendData(OopConstants.ChannelBindingLabelV1);
        h.AppendData(transcriptHashSha384);
        return h.GetHashAndReset();
    }

    private static void AppendLengthPrefixed(IncrementalHash h, byte[] bytes)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)bytes.Length);
        h.AppendData(len);
        h.AppendData(bytes);
    }
}