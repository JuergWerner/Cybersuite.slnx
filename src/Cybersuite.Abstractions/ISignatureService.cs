using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Digital signature service contract. Supports classical (ECDSA, RSA), PQC (ML-DSA / Dilithium),
/// and hybrid signature schemes.
/// Part of the provider service model defined in [PM-000].
/// 
/// Typical flow:
/// 1. Signer calls <see cref="GenerateKeyPair"/> ? gets <see cref="SignatureKeyPair"/>
///    (public key + opaque private key handle).
/// 2. Signer calls <see cref="Sign"/> with private key handle + message ? fills signature buffer.
/// 3. Verifier calls <see cref="Verify"/> with public key + message + signature ? boolean result.
/// 
/// Security: private key material never leaves the provider boundary as raw bytes.
/// The <see cref="Verify"/> method does not require a handle — it operates on the public key
/// bytes directly, which are inherently non-secret.
/// Thread-safety: implementations must be safe for concurrent use (per <see cref="ICryptoService"/>).
/// </summary>
public interface ISignatureService : ICryptoService
{
    /// <summary>Public key size in bytes for this algorithm.</summary>
    int PublicKeySize { get; }

    /// <summary>Signature size in bytes for this algorithm.</summary>
    int SignatureSize { get; }

    /// <summary>Generates a fresh signature key pair (public key + private key handle).</summary>
    SignatureKeyPair GenerateKeyPair();

    /// <summary>
    /// Signs a message using the private key handle. The signature is written to <paramref name="signatureOut"/>.
    /// </summary>
    void Sign(PrivateKeyHandle privateKey, ReadOnlySpan<byte> message, Span<byte> signatureOut);

    /// <summary>
    /// Verifies a signature over a message using the given public key.
    /// Returns true if the signature is valid, false otherwise.
    /// </summary>
    bool Verify(in PublicKey publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
}