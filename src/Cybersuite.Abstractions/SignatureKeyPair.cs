namespace Cybersuite.Abstractions;

/// <summary>
/// Signature key pair: public key (transmittable) + private key handle (opaque, provider-resident).
/// Returned by <see cref="ISignatureService.GenerateKeyPair"/>.
/// 
/// The <see cref="PublicKey"/> is distributed for verification; the <see cref="PrivateKey"/>
/// handle stays inside the provider boundary for signing operations.
/// </summary>
public readonly record struct SignatureKeyPair(PublicKey PublicKey, PrivateKeyHandle PrivateKey);