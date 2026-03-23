using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Xunit;

namespace Cybersuite.Tests.Integration;

/// <summary>
/// End-to-end live cryptographic round-trip tests through the BouncyCastle provider connection.
/// Validates real KEM (ECDH-P384, ML-KEM), Signature (ECDSA-P384, ML-DSA), AEAD (AES-256-GCM),
/// KDF (HKDF-SHA384), and handle destruction per [PH-023], [PH-024], [PH-025].
/// </summary>
public sealed class LiveCryptoRoundTripTests : IAsyncDisposable
{
    private readonly BouncyCastleProviderConnection _conn;
    private byte[] _channelBinding = null!;
    private ulong _counter;

    public LiveCryptoRoundTripTests()
    {
        string entrypoint = typeof(BouncyCastleProviderConnection).Assembly.Location;
        string root = Path.GetDirectoryName(entrypoint)!;
        var pkg = BouncyCastleManifestFactory.CreateInProcessPackage(root, entrypoint);
        _conn = new BouncyCastleProviderConnection(pkg);
        InitializeHandshake().GetAwaiter().GetResult();
    }

    private async Task InitializeHandshake()
    {
        var nonce = new byte[OopConstants.NonceSizeBytes];
        RandomNumberGenerator.Fill(nonce);

        var clientHello = new ClientHello(
            ProtocolVersion.V1_0, nonce, new byte[48],
            ExecutionProfile.Dev, false, true, null, null, null);

        var providerHello = await _conn.HandshakeAsync(clientHello, CancellationToken.None);

        byte[] transcript = HandshakeTranscript.ComputeTranscriptHashSha384(clientHello, providerHello);
        _channelBinding = HandshakeTranscript.ComputeChannelBindingSha384(transcript);
    }

    private OopRequestHeader Header(OopMessageType type) =>
        new(ProtocolVersion.V1_0, type, Handle128.NewRandom(), ++_counter, _channelBinding);

    public async ValueTask DisposeAsync() => await _conn.DisposeAsync();

    // ?? ECDH-P384-KEM: full round-trip ??

    [Fact]
    public async Task EcdhP384Kem_FullRoundTrip()
    {
        var algId = new AlgorithmId("ECDH-P384-KEM");

        // Generate receiver key pair
        var genResp = await _conn.KemGenerateKeyPairAsync(
            new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), algId),
            CancellationToken.None);
        Assert.True(genResp.KeyPair.PublicKey.Length > 0);

        // Encapsulate (sender side)
        var encResp = await _conn.KemEncapsulateAsync(
            new KemEncapsulateRequest(Header(OopMessageType.KemEncapsulateRequest), algId, genResp.KeyPair.PublicKey),
            CancellationToken.None);
        Assert.True(encResp.Result.Ciphertext.Length > 0);

        // Decapsulate (receiver side)
        var decResp = await _conn.KemDecapsulateAsync(
            new KemDecapsulateRequest(Header(OopMessageType.KemDecapsulateRequest), algId,
                genResp.KeyPair.PrivateKey, encResp.Result.Ciphertext.Span),
            CancellationToken.None);

        // Both sides should have derived shared secrets (handles are opaque, but they should not throw)
        Assert.NotEqual(default, decResp.SharedSecret);
    }

    // ?? ECDSA-P384: sign + verify ??

    [Fact]
    public async Task EcdsaP384_SignVerify_RoundTrip()
    {
        var algId = new AlgorithmId("ECDSA-P384");

        var genResp = await _conn.SignatureGenerateKeyPairAsync(
            new SignatureGenerateKeyPairRequest(Header(OopMessageType.SignatureGenerateKeyPairRequest), algId),
            CancellationToken.None);
        Assert.True(genResp.KeyPair.PublicKey.Length > 0);

        byte[] message = "test message for ECDSA-P384"u8.ToArray();

        var signResp = await _conn.SignatureSignAsync(
            new SignatureSignRequest(Header(OopMessageType.SignatureSignRequest), algId,
                genResp.KeyPair.PrivateKey, message),
            CancellationToken.None);
        Assert.True(signResp.Signature.Length > 0);

        var verifyResp = await _conn.SignatureVerifyAsync(
            new SignatureVerifyRequest(Header(OopMessageType.SignatureVerifyRequest), algId,
                genResp.KeyPair.PublicKey, message, signResp.Signature.Span),
            CancellationToken.None);
        Assert.True(verifyResp.IsValid);
    }

    // ?? ECDSA-P384: verify with wrong message fails ??

    [Fact]
    public async Task EcdsaP384_VerifyWrongMessage_ReturnsFalse()
    {
        var algId = new AlgorithmId("ECDSA-P384");

        var genResp = await _conn.SignatureGenerateKeyPairAsync(
            new SignatureGenerateKeyPairRequest(Header(OopMessageType.SignatureGenerateKeyPairRequest), algId),
            CancellationToken.None);

        byte[] message = "original"u8.ToArray();
        byte[] tampered = "tampered"u8.ToArray();

        var signResp = await _conn.SignatureSignAsync(
            new SignatureSignRequest(Header(OopMessageType.SignatureSignRequest), algId,
                genResp.KeyPair.PrivateKey, message),
            CancellationToken.None);

        var verifyResp = await _conn.SignatureVerifyAsync(
            new SignatureVerifyRequest(Header(OopMessageType.SignatureVerifyRequest), algId,
                genResp.KeyPair.PublicKey, tampered, signResp.Signature.Span),
            CancellationToken.None);
        Assert.False(verifyResp.IsValid);
    }

    // ?? AES-256-GCM: encrypt + decrypt ??

    [Fact]
    public async Task Aes256Gcm_EncryptDecrypt_RoundTrip()
    {
        var algId = new AlgorithmId("AES-256-GCM");

        var genResp = await _conn.AeadGenerateKeyAsync(
            new AeadGenerateKeyRequest(Header(OopMessageType.AeadGenerateKeyRequest), algId),
            CancellationToken.None);

        byte[] plaintext = "secret data to encrypt with AES-256-GCM"u8.ToArray();
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] aad = "associated data"u8.ToArray();

        var encResp = await _conn.AeadEncryptAsync(
            new AeadEncryptRequest(Header(OopMessageType.AeadEncryptRequest), algId,
                genResp.KeyHandle, nonce, plaintext, aad),
            CancellationToken.None);
        Assert.True(encResp.Ciphertext.Length > 0);

        var decResp = await _conn.AeadDecryptAsync(
            new AeadDecryptRequest(Header(OopMessageType.AeadDecryptRequest), algId,
                genResp.KeyHandle, nonce, encResp.Ciphertext.Span, aad),
            CancellationToken.None);
        Assert.True(decResp.IsValid);
        Assert.True(decResp.Plaintext.Span.SequenceEqual(plaintext));
    }

    // ?? AES-256-GCM: tampered ciphertext fails ??

    [Fact]
    public async Task Aes256Gcm_TamperedCiphertext_DecryptFails()
    {
        var algId = new AlgorithmId("AES-256-GCM");

        var genResp = await _conn.AeadGenerateKeyAsync(
            new AeadGenerateKeyRequest(Header(OopMessageType.AeadGenerateKeyRequest), algId),
            CancellationToken.None);

        byte[] plaintext = "data"u8.ToArray();
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);

        var encResp = await _conn.AeadEncryptAsync(
            new AeadEncryptRequest(Header(OopMessageType.AeadEncryptRequest), algId,
                genResp.KeyHandle, nonce, plaintext, ReadOnlySpan<byte>.Empty),
            CancellationToken.None);

        byte[] tampered = encResp.Ciphertext.ToArray();
        tampered[0] ^= 0xFF; // flip a byte

        var decResp = await _conn.AeadDecryptAsync(
            new AeadDecryptRequest(Header(OopMessageType.AeadDecryptRequest), algId,
                genResp.KeyHandle, nonce, tampered, ReadOnlySpan<byte>.Empty),
            CancellationToken.None);
        Assert.False(decResp.IsValid);
    }

    // ?? KDF: HKDF-SHA384 derive key ??

    [Fact]
    public async Task HkdfSha384_DeriveKey_Succeeds()
    {
        var kemAlg = new AlgorithmId("ECDH-P384-KEM");
        var kdfAlg = new AlgorithmId("HKDF-SHA384");

        // First generate a shared secret via KEM
        var genResp = await _conn.KemGenerateKeyPairAsync(
            new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), kemAlg),
            CancellationToken.None);

        var encResp = await _conn.KemEncapsulateAsync(
            new KemEncapsulateRequest(Header(OopMessageType.KemEncapsulateRequest), kemAlg, genResp.KeyPair.PublicKey),
            CancellationToken.None);

        // Derive a key from the shared secret
        var kdfResp = await _conn.KdfDeriveKeyAsync(
            new KdfDeriveKeyRequest(Header(OopMessageType.KdfDeriveKeyRequest), kdfAlg,
                encResp.Result.SharedSecret,
                new KdfParameters(
                    Salt: Array.Empty<byte>(),
                    Info: "test-context"u8.ToArray(),
                    OutputKeyBits: 256)),
            CancellationToken.None);

        Assert.NotEqual(default, kdfResp.SecretKeyHandle);
    }

    // ?? Handle destruction ??

    [Fact]
    public async Task DestroyHandle_PrivateKey_Succeeds()
    {
        var algId = new AlgorithmId("ECDH-P384-KEM");

        var genResp = await _conn.KemGenerateKeyPairAsync(
            new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), algId),
            CancellationToken.None);

        var destroyResp = await _conn.DestroyHandleAsync(
            new DestroyHandleRequest(Header(OopMessageType.DestroyHandleRequest),
                DestroyHandleKind.PrivateKey,
                genResp.KeyPair.PrivateKey.ProviderId,
                genResp.KeyPair.PrivateKey.Value),
            CancellationToken.None);

        Assert.True(destroyResp.Header.Success);
    }

    // ?? ML-KEM: PQC key encapsulation round-trip ??
    // Per [PH-023]: PQC-Live-Binding darf fail-closed mit NotSupportedException enden,
    // wenn die installierte BC-Version die erwarteten PQC-Typen nicht tatsächlich exponiert.

    [Theory]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public async Task MlKem_FullRoundTrip(string algorithmName)
    {
        var algId = new AlgorithmId(algorithmName);

        KemGenerateKeyPairResponse genResp;
        try
        {
            genResp = await _conn.KemGenerateKeyPairAsync(
                new KemGenerateKeyPairRequest(Header(OopMessageType.KemGenerateKeyPairRequest), algId),
                CancellationToken.None);
        }
        catch (NotSupportedException)
        {
            // Expected fail-closed when BC package lacks PQC types per [PH-023]
            return;
        }

        Assert.True(genResp.KeyPair.PublicKey.Length > 0);

        var encResp = await _conn.KemEncapsulateAsync(
            new KemEncapsulateRequest(Header(OopMessageType.KemEncapsulateRequest), algId, genResp.KeyPair.PublicKey),
            CancellationToken.None);
        Assert.True(encResp.Result.Ciphertext.Length > 0);

        var decResp = await _conn.KemDecapsulateAsync(
            new KemDecapsulateRequest(Header(OopMessageType.KemDecapsulateRequest), algId,
                genResp.KeyPair.PrivateKey, encResp.Result.Ciphertext.Span),
            CancellationToken.None);
        Assert.NotEqual(default, decResp.SharedSecret);
    }

    // ?? ML-DSA: PQC signature round-trip ??
    // Per [PH-023]: fail-closed when BC types unavailable.

    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public async Task MlDsa_SignVerify_RoundTrip(string algorithmName)
    {
        var algId = new AlgorithmId(algorithmName);

        SignatureGenerateKeyPairResponse genResp;
        try
        {
            genResp = await _conn.SignatureGenerateKeyPairAsync(
                new SignatureGenerateKeyPairRequest(Header(OopMessageType.SignatureGenerateKeyPairRequest), algId),
                CancellationToken.None);
        }
        catch (NotSupportedException)
        {
            // Expected fail-closed when BC package lacks PQC types per [PH-023]
            return;
        }

        Assert.True(genResp.KeyPair.PublicKey.Length > 0);

        byte[] message = System.Text.Encoding.UTF8.GetBytes($"PQC test message for {algorithmName}");

        var signResp = await _conn.SignatureSignAsync(
            new SignatureSignRequest(Header(OopMessageType.SignatureSignRequest), algId,
                genResp.KeyPair.PrivateKey, message),
            CancellationToken.None);
        Assert.True(signResp.Signature.Length > 0);

        var verifyResp = await _conn.SignatureVerifyAsync(
            new SignatureVerifyRequest(Header(OopMessageType.SignatureVerifyRequest), algId,
                genResp.KeyPair.PublicKey, message, signResp.Signature.Span),
            CancellationToken.None);
        Assert.True(verifyResp.IsValid);
    }

    // ?? ML-DSA: wrong message fails verification ??

    [Fact]
    public async Task MlDsa65_VerifyWrongMessage_ReturnsFalse()
    {
        var algId = new AlgorithmId("ML-DSA-65");

        SignatureGenerateKeyPairResponse genResp;
        try
        {
            genResp = await _conn.SignatureGenerateKeyPairAsync(
                new SignatureGenerateKeyPairRequest(Header(OopMessageType.SignatureGenerateKeyPairRequest), algId),
                CancellationToken.None);
        }
        catch (NotSupportedException)
        {
            // Expected fail-closed when BC package lacks PQC types per [PH-023]
            return;
        }

        var signResp = await _conn.SignatureSignAsync(
            new SignatureSignRequest(Header(OopMessageType.SignatureSignRequest), algId,
                genResp.KeyPair.PrivateKey, "original"u8.ToArray()),
            CancellationToken.None);

        var verifyResp = await _conn.SignatureVerifyAsync(
            new SignatureVerifyRequest(Header(OopMessageType.SignatureVerifyRequest), algId,
                genResp.KeyPair.PublicKey, "tampered"u8.ToArray(), signResp.Signature.Span),
            CancellationToken.None);
        Assert.False(verifyResp.IsValid);
    }

    // Strict mode: PQC must work with current BC package.
    // Per [PH-024]: ML-KEM-512 round-trip MUST succeed.

    [Fact]
    public async Task MlKem512_RoundTrip_Success()
    {
        // NO try-catch - test MUST pass or fail loudly
        var algId = new AlgorithmId("ML-KEM-512");

        var keyPairReq = new KemGenerateKeyPairRequest(
            Header(OopMessageType.KemGenerateKeyPairRequest), 
            algId);
        var keyPairResp = await _conn.KemGenerateKeyPairAsync(keyPairReq, CancellationToken.None);

        // These assertions will fail if PQC doesn't work
        Assert.True(keyPairResp.KeyPair.PublicKey.Length > 0);
        Assert.Equal(800, keyPairResp.KeyPair.PublicKey.Length); // ML-KEM-512 public key size

        // Complete the round-trip
        var encResp = await _conn.KemEncapsulateAsync(
            new KemEncapsulateRequest(Header(OopMessageType.KemEncapsulateRequest), algId, keyPairResp.KeyPair.PublicKey),
            CancellationToken.None);
        Assert.True(encResp.Result.Ciphertext.Length > 0);

        var decResp = await _conn.KemDecapsulateAsync(
            new KemDecapsulateRequest(Header(OopMessageType.KemDecapsulateRequest), algId,
                keyPairResp.KeyPair.PrivateKey, encResp.Result.Ciphertext.Span),
            CancellationToken.None);
        Assert.NotEqual(default, decResp.SharedSecret);
    }
}
