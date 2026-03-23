using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Key Encapsulation Mechanism (KEM) service contract.
/// Supports post-quantum KEMs (e.g., ML-KEM / Kyber) and hybrid constructions.
/// Part of the provider service model defined in [PM-000].
/// 
/// Typical flow:
/// 1. Receiver calls <see cref="GenerateKeyPair"/> ? gets <see cref="KemKeyPair"/>
///    (public key + opaque private key handle).
/// 2. Sender calls <see cref="Encapsulate"/> with the receiver's public key ?
///    gets <see cref="KemEncapsulationResult"/> (ciphertext + shared secret handle).
/// 3. Receiver calls <see cref="Decapsulate"/> with private key handle + ciphertext ?
///    gets <see cref="SharedSecretHandle"/>.
/// 4. Both sides feed the shared secret into <see cref="IKdfService.DeriveKey"/> to
///    produce symmetric keys.
/// 
/// Security: private keys and shared secrets never leave the provider boundary as raw bytes.
/// Thread-safety: implementations must be safe for concurrent use (per <see cref="ICryptoService"/>).
/// </summary>
public interface IKemService : ICryptoService
{
    /// <summary>Public key size in bytes for this algorithm.</summary>
    int PublicKeySize { get; }

    /// <summary>Ciphertext (encapsulation) size in bytes for this algorithm.</summary>
    int CiphertextSize { get; }

    /// <summary>Generates a fresh KEM key pair (public key + private key handle).</summary>
    KemKeyPair GenerateKeyPair();

    /// <summary>
    /// Encapsulates a shared secret using the recipient's public key.
    /// Returns the ciphertext to send and an opaque handle to the shared secret.
    /// </summary>
    KemEncapsulationResult Encapsulate(in PublicKey recipientPublicKey);

    /// <summary>
    /// Decapsulates a shared secret using the private key handle and received ciphertext.
    /// Returns an opaque handle to the derived shared secret.
    /// </summary>
    SharedSecretHandle Decapsulate(PrivateKeyHandle privateKey, ReadOnlySpan<byte> ciphertext);
}