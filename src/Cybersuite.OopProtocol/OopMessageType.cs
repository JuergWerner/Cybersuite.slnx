namespace Cybersuite.OopProtocol;

/// <summary>
/// Discriminator for all OPP request/response message types carried in
/// <see cref="Headers.OopRequestHeader"/> and <see cref="Headers.OopResponseHeader"/>.
/// Numeric ranges are grouped by domain: 1-9 = handshake, 10-19 = discovery,
/// 20-29 = health/lifecycle, 30-39 = KEM, 40-49 = signature, 50-59 = AEAD,
/// 60-69 = KDF, 70-79 = handle lifecycle, 100 = generic error.
/// </summary>
public enum OopMessageType : ushort
{
    // Handshake
    ClientHello = 1,
    ProviderHello = 2,

    // Discovery / capabilities
    CapabilityRequest = 10,
    CapabilityResponse = 11,

    // Health / lifecycle
    HealthRequest = 20,
    HealthResponse = 21,
    ShutdownRequest = 22,
    ShutdownResponse = 23,

    // KEM
    KemGenerateKeyPairRequest = 30,
    KemGenerateKeyPairResponse = 31,
    KemEncapsulateRequest = 32,
    KemEncapsulateResponse = 33,
    KemDecapsulateRequest = 34,
    KemDecapsulateResponse = 35,

    // Signature
    SignatureGenerateKeyPairRequest = 40,
    SignatureGenerateKeyPairResponse = 41,
    SignatureSignRequest = 42,
    SignatureSignResponse = 43,
    SignatureVerifyRequest = 44,
    SignatureVerifyResponse = 45,

    // AEAD
    AeadGenerateKeyRequest = 50,
    AeadGenerateKeyResponse = 51,
    AeadEncryptRequest = 52,
    AeadEncryptResponse = 53,
    AeadDecryptRequest = 54,
    AeadDecryptResponse = 55,

    // KDF
    KdfDeriveKeyRequest = 60,
    KdfDeriveKeyResponse = 61,

    // Handle lifecycle
    DestroyHandleRequest = 70,
    DestroyHandleResponse = 71,

    // Generic errors
    Error = 100
}