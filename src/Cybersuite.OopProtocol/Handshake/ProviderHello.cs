using System;
using Cybersuite.ProviderModel;

namespace Cybersuite.OopProtocol.Handshake;

/// <summary>
/// Provider to Core handshake message. Binds ProviderIdentity, capability hash, and the provider's
/// canonical compliance envelope into the handshake transcript.
/// </summary>
public sealed class ProviderHello
{
    public ProtocolVersion Version { get; }
    public ReadOnlyMemory<byte> Nonce { get; }

    public ProviderIdentity Identity { get; }
    public ReadOnlyMemory<byte> CapabilityHashSha384 { get; }

    public ProviderComplianceEnvelope ComplianceEnvelope { get; }
    public bool FipsBoundaryDeclared { get; }
    public bool IsExperimental { get; }

    /// <summary>
    /// Optional opaque attestation evidence (format TBD).
    /// </summary>
    public ReadOnlyMemory<byte>? AttestationEvidence { get; }

    public ProviderHello(
        ProtocolVersion version,
        ReadOnlySpan<byte> nonce32,
        ProviderIdentity identity,
        ReadOnlySpan<byte> capabilityHashSha384,
        bool fipsBoundaryDeclared,
        bool isExperimental,
        ReadOnlyMemory<byte>? attestationEvidence)
        : this(
            version,
            nonce32,
            identity,
            capabilityHashSha384,
            ProviderComplianceEnvelope.FromLegacyHandshake(fipsBoundaryDeclared),
            isExperimental,
            attestationEvidence)
    {
    }

    public ProviderHello(
        ProtocolVersion version,
        ReadOnlySpan<byte> nonce32,
        ProviderIdentity identity,
        ReadOnlySpan<byte> capabilityHashSha384,
        ProviderComplianceEnvelope complianceEnvelope,
        bool isExperimental,
        ReadOnlyMemory<byte>? attestationEvidence)
    {
        if (nonce32.Length != OopConstants.NonceSizeBytes)
            throw new ArgumentException("Nonce must be 32 bytes.", nameof(nonce32));

        if (capabilityHashSha384.Length != OopConstants.Sha384SizeBytes)
            throw new ArgumentException("CapabilityHashSha384 must be 48 bytes (SHA-384).", nameof(capabilityHashSha384));

        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        ComplianceEnvelope = complianceEnvelope ?? throw new ArgumentNullException(nameof(complianceEnvelope));
        Version = version;

        var n = new byte[OopConstants.NonceSizeBytes];
        nonce32.CopyTo(n);
        Nonce = n;

        var ch = new byte[OopConstants.Sha384SizeBytes];
        capabilityHashSha384.CopyTo(ch);
        CapabilityHashSha384 = ch;

        FipsBoundaryDeclared = complianceEnvelope.DeclaredValidatedBoundary;
        IsExperimental = isExperimental;

        if (attestationEvidence is null || attestationEvidence.Value.IsEmpty)
        {
            AttestationEvidence = null;
        }
        else
        {
            var copy = attestationEvidence.Value.ToArray();
            AttestationEvidence = copy;
        }
    }

    public byte[] ToCanonicalBytes() => OopWireFormat.EncodeProviderHello(this);
}
