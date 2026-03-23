using System;
using System.Collections.Immutable;

namespace Cybersuite.Policy;

/// <summary>
/// Signature envelope attached to a policy (either embedded under top-level "signature" or provided via sidecar).
/// This envelope is NOT included in canonicalization.
/// </summary>
public sealed class PolicySignatureEnvelope
{
    public PolicySignatureAlgorithm Algorithm { get; }
    public ReadOnlyMemory<byte> SignatureBytes { get; }

    /// <summary>DER encoded signer certificate (leaf).</summary>
    public ReadOnlyMemory<byte> SignerCertificateDer { get; }

    /// <summary>Optional DER encoded intermediate certs.</summary>
    public ImmutableArray<ReadOnlyMemory<byte>> AdditionalCertificatesDer { get; }

    public PolicySignatureEnvelope(
        PolicySignatureAlgorithm algorithm,
        ReadOnlyMemory<byte> signatureBytes,
        ReadOnlyMemory<byte> signerCertificateDer,
        ImmutableArray<ReadOnlyMemory<byte>> additionalCertificatesDer)
    {
        Algorithm = algorithm;
        SignatureBytes = signatureBytes;
        SignerCertificateDer = signerCertificateDer;
        AdditionalCertificatesDer = additionalCertificatesDer;
    }
}