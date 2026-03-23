using System.Collections.Immutable;

namespace Cybersuite.Abstractions;

/// <summary>
/// A provider session is a stable, policy-bound context for crypto operations.
/// Sessions are created by the ProviderHost after a successful OOP handshake and
/// channel-binding verification [ARC-500]. Each session is bound to exactly one
/// policy hash (SHA-384) and one provider identity.
/// Contract: thread-safe (multi-thread reentrant). Dispose releases provider-side resources.
/// The session exposes factory methods for typed crypto services (KEM, Signature, AEAD, KDF)
/// and handle lifecycle management for private keys, secret keys, and shared secrets.
/// </summary>
public interface IProviderSession : IDisposable
{
    ProviderId ProviderId { get; }

    /// <summary>
    /// Indicates the provider claims to operate within a FIPS boundary for this session (informational).
    /// Compliance enforcement uses allowlists/flags; certification is provider responsibility.
    /// </summary>
    bool FipsBoundaryActive { get; }

    /// <summary>Capabilities snapshot for the session lifetime (immutable).</summary>
    ImmutableArray<AlgorithmDescriptor> Capabilities { get; }

    /// <summary>Returns a KEM service for the specified algorithm. Throws if the algorithm is not available.</summary>
    IKemService GetKem(AlgorithmId algorithmId);

    /// <summary>Returns a signature service for the specified algorithm. Throws if the algorithm is not available.</summary>
    ISignatureService GetSignature(AlgorithmId algorithmId);

    /// <summary>Returns an AEAD service for the specified algorithm. Throws if the algorithm is not available.</summary>
    IAeadService GetAead(AlgorithmId algorithmId);

    /// <summary>Returns a KDF service for the specified algorithm. Throws if the algorithm is not available.</summary>
    IKdfService GetKdf(AlgorithmId algorithmId);

    // Handle lifecycle

    /// <summary>Requests zeroization and release of the private key material referenced by this handle.</summary>
    void Destroy(PrivateKeyHandle handle);

    /// <summary>Requests zeroization and release of the symmetric key material referenced by this handle.</summary>
    void Destroy(SecretKeyHandle handle);

    /// <summary>Requests zeroization and release of the shared secret material referenced by this handle.</summary>
    void Destroy(SharedSecretHandle handle);
}