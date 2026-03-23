using System;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Messages;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Abstraction over a single connection to a cryptographic provider.
/// Exposes the full OPP message surface: handshake, capability query,
/// health, shutdown, plus KEM, signature, AEAD, KDF, and handle-destroy
/// operations. Implementations may run in-process (e.g. BouncyCastle) or
/// out-of-process behind a transport layer.
/// </summary>
public interface IProviderConnection : IAsyncDisposable
{
    ValueTask<ProviderHello> HandshakeAsync(ClientHello clientHello, CancellationToken cancellationToken);

    ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken);

    ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken);

    ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken);

    ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken);
    ValueTask<KemEncapsulateResponse> KemEncapsulateAsync(KemEncapsulateRequest request, CancellationToken cancellationToken);
    ValueTask<KemDecapsulateResponse> KemDecapsulateAsync(KemDecapsulateRequest request, CancellationToken cancellationToken);

    ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken);
    ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken);
    ValueTask<SignatureVerifyResponse> SignatureVerifyAsync(SignatureVerifyRequest request, CancellationToken cancellationToken);

    ValueTask<AeadGenerateKeyResponse> AeadGenerateKeyAsync(AeadGenerateKeyRequest request, CancellationToken cancellationToken);
    ValueTask<AeadEncryptResponse> AeadEncryptAsync(AeadEncryptRequest request, CancellationToken cancellationToken);
    ValueTask<AeadDecryptResponse> AeadDecryptAsync(AeadDecryptRequest request, CancellationToken cancellationToken);

    ValueTask<KdfDeriveKeyResponse> KdfDeriveKeyAsync(KdfDeriveKeyRequest request, CancellationToken cancellationToken);

    ValueTask<DestroyHandleResponse> DestroyHandleAsync(DestroyHandleRequest request, CancellationToken cancellationToken);
}