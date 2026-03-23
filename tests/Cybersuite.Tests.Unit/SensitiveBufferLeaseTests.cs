using System;
using System.Buffers;
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Cybersuite.Provider.BouncyCastle;
using Xunit;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// F5-FIX: Tests for <see cref="SensitiveBufferLease"/> and the pooled lease
/// methods on <see cref="BouncyCastleKeyMaterialStore"/>.
/// Validates lifecycle, zeroization, and integration with provider operations.
/// </summary>
public sealed class SensitiveBufferLeaseTests
{
    // ─────────────────────────────────────────────────────────
    //  SensitiveBufferLease core lifecycle
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void Rent_ReturnsLeaseWithCorrectLength()
    {
        using var lease = SensitiveBufferLease.Rent(32);
        Assert.Equal(32, lease.Length);
        Assert.Equal(32, lease.Span.Length);
        Assert.Equal(32, lease.ReadOnlySpan.Length);
    }

    [Fact]
    public void CopyFrom_CopiesDataExactly()
    {
        byte[] source = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        using var lease = SensitiveBufferLease.CopyFrom(source);

        Assert.Equal(source.Length, lease.Length);
        Assert.True(lease.ReadOnlySpan.SequenceEqual(source));
    }

    [Fact]
    public void Dispose_ZeroizesBuffer()
    {
        var lease = SensitiveBufferLease.CopyFrom(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        byte[] array = lease.DangerousGetArray();
        int length = lease.Length;

        // Pre-condition: data is present
        Assert.True(array.AsSpan(0, length).IndexOfAnyExcept((byte)0) >= 0,
            "Buffer should contain non-zero data before dispose.");

        lease.Dispose();

        // Post-condition: used portion is zeroed
        Assert.True(array.AsSpan(0, length).ContainsAnyExcept((byte)0) == false,
            "Buffer should be zeroized after dispose.");
    }

    [Fact]
    public void Dispose_IsIdempotent()
    {
        var lease = SensitiveBufferLease.CopyFrom(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF });

        lease.Dispose();
        lease.Dispose(); // Must not throw (double-return to pool is guarded)
    }

    [Fact]
    public void Span_AfterDispose_Throws()
    {
        var lease = SensitiveBufferLease.Rent(16);
        lease.Dispose();

        Assert.Throws<ObjectDisposedException>(() => _ = lease.Span);
    }

    [Fact]
    public void DangerousGetArray_AfterDispose_Throws()
    {
        var lease = SensitiveBufferLease.Rent(16);
        lease.Dispose();

        Assert.Throws<ObjectDisposedException>(() => lease.DangerousGetArray());
    }

    [Fact]
    public void Rent_ZeroLength_Succeeds()
    {
        using var lease = SensitiveBufferLease.Rent(0);
        Assert.Equal(0, lease.Length);
    }

    [Fact]
    public void DangerousGetArray_MayBeLargerThanLength()
    {
        using var lease = SensitiveBufferLease.Rent(17);
        byte[] array = lease.DangerousGetArray();

        // ArrayPool may return a larger buffer
        Assert.True(array.Length >= 17);
        // But Span is exactly the requested length
        Assert.Equal(17, lease.Span.Length);
    }

    // ─────────────────────────────────────────────────────────
    //  KeyMaterialStore lease integration
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void LeaseSecretKey_ReturnsCorrectData()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var providerId = new ProviderId("Test");
        byte[] keyMaterial = new byte[32];
        RandomNumberGenerator.Fill(keyMaterial);

        var handle = store.AddSecretKey(providerId, keyMaterial);
        using var lease = store.LeaseSecretKey(handle);

        Assert.Equal(32, lease.Length);
        Assert.True(lease.ReadOnlySpan.SequenceEqual(keyMaterial));
    }

    [Fact]
    public void LeaseSharedSecret_ReturnsCorrectData()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var providerId = new ProviderId("Test");
        byte[] secretMaterial = new byte[48];
        RandomNumberGenerator.Fill(secretMaterial);

        var handle = store.AddSharedSecret(providerId, secretMaterial);
        using var lease = store.LeaseSharedSecret(handle);

        Assert.Equal(48, lease.Length);
        Assert.True(lease.ReadOnlySpan.SequenceEqual(secretMaterial));
    }

    [Fact]
    public void LeaseSecretKey_InvalidHandle_Throws()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var bogus = new SecretKeyHandle(new ProviderId("Test"), Guid.NewGuid());

        Assert.Throws<InvalidOperationException>(() => store.LeaseSecretKey(bogus));
    }

    [Fact]
    public void LeaseSharedSecret_InvalidHandle_Throws()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var bogus = new SharedSecretHandle(new ProviderId("Test"), Guid.NewGuid());

        Assert.Throws<InvalidOperationException>(() => store.LeaseSharedSecret(bogus));
    }

    [Fact]
    public void LeaseSecretKey_DisposedLease_DoesNotAffectStore()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var providerId = new ProviderId("Test");
        byte[] keyMaterial = new byte[32];
        RandomNumberGenerator.Fill(keyMaterial);

        var handle = store.AddSecretKey(providerId, keyMaterial);

        // Lease and dispose
        var lease1 = store.LeaseSecretKey(handle);
        lease1.Dispose();

        // Store should still have the key — second lease should work
        using var lease2 = store.LeaseSecretKey(handle);
        Assert.True(lease2.ReadOnlySpan.SequenceEqual(keyMaterial),
            "Store data must survive lease disposal (lease holds a copy, not the original).");
    }

    // ─────────────────────────────────────────────────────────
    //  AEAD message zeroization
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void AeadEncryptRequest_Dispose_ZeroizesPlaintext()
    {
        byte[] plaintext = [1, 2, 3, 4, 5, 6, 7, 8];
        var request = new Cybersuite.OopProtocol.Messages.AeadEncryptRequest(
            CreateDummyRequestHeader(),
            new AlgorithmId("AES-256-GCM"),
            new SecretKeyHandle(new ProviderId("T"), Guid.NewGuid()),
            nonce: new byte[12],
            plaintext: plaintext,
            associatedData: ReadOnlySpan<byte>.Empty);

        // Plaintext should have data
        Assert.True(request.Plaintext.Span.IndexOfAnyExcept((byte)0) >= 0);

        request.Dispose();

        // After dispose, the internal plaintext array should be zeroed
        Assert.True(request.Plaintext.Span.ContainsAnyExcept((byte)0) == false,
            "Plaintext should be zeroized after dispose.");
    }

    [Fact]
    public void AeadDecryptResponse_Dispose_ZeroizesPlaintext()
    {
        byte[] pt = [0xAA, 0xBB, 0xCC, 0xDD];
        var response = new Cybersuite.OopProtocol.Messages.AeadDecryptResponse(
            CreateDummyResponseHeader(),
            isValid: true,
            plaintext: pt);

        Assert.True(response.Plaintext.Span.IndexOfAnyExcept((byte)0) >= 0);

        response.Dispose();

        Assert.True(response.Plaintext.Span.ContainsAnyExcept((byte)0) == false,
            "Plaintext should be zeroized after dispose.");
    }

    // ─────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────

    private static Cybersuite.OopProtocol.Headers.OopRequestHeader CreateDummyRequestHeader()
        => new(
            version: Cybersuite.OopProtocol.ProtocolVersion.V1_0,
            messageType: Cybersuite.OopProtocol.OopMessageType.AeadEncryptRequest,
            requestId: Cybersuite.OopProtocol.Handle128.NewRandom(),
            messageCounter: 1,
            channelBindingSha384: new byte[48]);

    private static Cybersuite.OopProtocol.Headers.OopResponseHeader CreateDummyResponseHeader()
        => new(
            version: Cybersuite.OopProtocol.ProtocolVersion.V1_0,
            messageType: Cybersuite.OopProtocol.OopMessageType.AeadDecryptResponse,
            requestId: Cybersuite.OopProtocol.Handle128.NewRandom(),
            messageCounter: 1,
            channelBindingSha384: new byte[48],
            success: true,
            error: null);
}
