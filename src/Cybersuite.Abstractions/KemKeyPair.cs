namespace Cybersuite.Abstractions;

/// <summary>
/// KEM key pair: public key (transmittable) + private key handle (opaque, provider-resident).
/// Returned by <see cref="IKemService.GenerateKeyPair"/>.
/// 
/// The <see cref="PublicKey"/> is sent to the encapsulator; the <see cref="PrivateKey"/> handle
/// stays inside the provider boundary for decapsulation.
/// </summary>
public readonly record struct KemKeyPair(PublicKey PublicKey, PrivateKeyHandle PrivateKey);