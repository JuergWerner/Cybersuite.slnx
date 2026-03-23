namespace Cybersuite.Abstractions;

/// <summary>
/// Key Derivation Function (KDF) service contract (e.g., HKDF-SHA384).
/// Part of the provider service model defined in [PM-000].
/// 
/// Takes an opaque <see cref="SharedSecretHandle"/> (e.g., output of KEM decapsulation)
/// and derives a symmetric key (<see cref="SecretKeyHandle"/>) using the supplied
/// <see cref="KdfParameters"/> (salt, info/context, output size).
/// 
/// Both input and output are opaque handles — the raw secret material never leaves
/// the provider trust boundary, which is the fundamental design principle of
/// handle-based secret management per [OOP-040] and [ARC-010].
/// 
/// Thread-safety: implementations must be safe for concurrent use (per <see cref="ICryptoService"/>).
/// </summary>
public interface IKdfService : ICryptoService
{
    /// <summary>
    /// Derives a symmetric key from a shared secret using the given KDF parameters.
    /// Returns an opaque handle to the derived key material.
    /// </summary>
    SecretKeyHandle DeriveKey(SharedSecretHandle sharedSecret, in KdfParameters parameters);
}