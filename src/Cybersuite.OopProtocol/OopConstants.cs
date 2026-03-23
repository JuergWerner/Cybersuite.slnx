using System.Text;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Protocol-wide constants for the Out-of-Process Protocol (OPP).
/// Includes fixed sizes for SHA-384 hashes, nonces, and 128-bit handles,
/// as well as ASCII domain-separation labels used by <see cref="Handshake.HandshakeTranscript"/>
/// to derive transcript and channel-binding values.
/// </summary>
public static class OopConstants
{
    /// <summary>Size of SHA-384 hash digests in bytes (48). Used for policy hashes, capability hashes, transcript hashes, and channel bindings.</summary>
    public const int Sha384SizeBytes = 48;

    /// <summary>Size of handshake nonces in bytes (32). ClientHello and ProviderHello each carry a 256-bit nonce for freshness.</summary>
    public const int NonceSizeBytes = 32;

    /// <summary>Size of opaque <see cref="Handle128"/> identifiers in bytes (16 = 128 bits).</summary>
    public const int HandleSizeBytes = 16;

    // Domain separation labels (stable, ASCII)
    internal static readonly byte[] TranscriptLabelV1 = Encoding.ASCII.GetBytes("Cybersuite.OPP.TranscriptV1");
    internal static readonly byte[] ChannelBindingLabelV1 = Encoding.ASCII.GetBytes("Cybersuite.OPP.ChannelBindingV1");
}