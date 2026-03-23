using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Public key material associated with a specific algorithm.
/// Part of the key pair model used in <see cref="IKemService"/> and <see cref="ISignatureService"/>.
/// 
/// Unlike private keys (represented as opaque <see cref="PrivateKeyHandle"/>), public keys
/// contain actual byte data because they are inherently non-secret and need to be transmitted
/// across trust boundaries (e.g., for KEM encapsulation or signature verification).
/// 
/// The <see cref="AlgorithmId"/> field binds the key to a specific algorithm, preventing
/// accidental misuse of a public key with an incompatible algorithm.
/// </summary>
public readonly record struct PublicKey(AlgorithmId AlgorithmId, ReadOnlyMemory<byte> Bytes)
{
    /// <summary>Length of the public key in bytes.</summary>
    public int Length => Bytes.Length;
}