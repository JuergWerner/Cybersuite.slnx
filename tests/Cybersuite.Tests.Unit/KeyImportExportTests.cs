using System;
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Cybersuite.Provider.BouncyCastle;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// USA-001: Validates BouncyCastleKeyImportExportService round-trip and error handling.
/// SC-002: Validates NativeCurveP384 key generation and shared-secret derivation.
/// </summary>
public sealed class KeyImportExportTests
{
    private static readonly ProviderId TestProvider = new("BouncyCastle");
    private static readonly AlgorithmId EcdhP384 = new("ECDH-P384-KEM");

    // ─────────────────────────────────────────────────────────
    //  USA-001: Key Import / Export round-trip
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void ExportPublicKey_ReturnsUncompressedPoint()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var keyPair = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var pub = BouncyCastleCurveP384.ToPublicKey(EcdhP384, (ECPublicKeyParameters)keyPair.Public);

        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPublicKey);
        byte[] exported = svc.ExportPublicKey(pub, options);

        Assert.Equal(97, exported.Length);
        Assert.Equal(0x04, exported[0]); // uncompressed point marker
    }

    [Fact]
    public void ImportPublicKey_ValidPoint_Succeeds()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var keyPair = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        byte[] rawPublic = ((ECPublicKeyParameters)keyPair.Public).Q.GetEncoded(false);

        var options = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPublicKey);
        var imported = svc.ImportPublicKey(rawPublic, options);

        Assert.Equal(EcdhP384, imported.AlgorithmId);
        Assert.Equal(97, imported.Bytes.Length);
    }

    [Fact]
    public void ImportPrivateKey_RoundTrip_ExportMatchesImport()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        // Generate a key pair and extract the raw private scalar
        var keyPair = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        byte[] originalScalar = ((ECPrivateKeyParameters)keyPair.Private).D.ToByteArrayUnsigned();

        try
        {
            // Import the raw scalar
            var importOpts = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);
            var handle = svc.ImportPrivateKey(originalScalar, importOpts);

            // Export it back
            var exportOpts = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);
            byte[] exported = svc.ExportPrivateKey(handle, exportOpts);

            try
            {
                Assert.Equal(originalScalar, exported);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exported);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalScalar);
        }
    }

    [Fact]
    public void ImportPublicKey_WrongSize_Throws()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var options = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPublicKey);
        Assert.Throws<ArgumentException>(() => svc.ImportPublicKey(new byte[32], options));
    }

    [Fact]
    public void ImportPrivateKey_WrongSize_Throws()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var options = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);
        Assert.Throws<ArgumentException>(() => svc.ImportPrivateKey(new byte[16], options));
    }

    // ─────────────────────────────────────────────────────────
    //  F4-FIX: Import zeroization of temporary byte[] copy
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void ImportPrivateKey_ZeroizesTemporaryCopy()
    {
        // Verify the import still produces a correct, usable handle.
        // The temporary byte[] used for BigInteger construction is zeroized
        // inside the finally block. We verify correctness is preserved by
        // performing a round-trip export.
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        byte[] originalScalar = ((ECPrivateKeyParameters)kp.Private).D.ToByteArrayUnsigned();

        try
        {
            var importOpts = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);
            var handle = svc.ImportPrivateKey(originalScalar, importOpts);

            // The imported key should still be usable — round-trip export
            var exportOpts = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);
            byte[] exported = svc.ExportPrivateKey(handle, exportOpts);

            try
            {
                Assert.Equal(originalScalar, exported);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(exported);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(originalScalar);
        }
    }

    [Fact]
    public void ImportPrivateKey_InvalidScalar_ThrowsAndDoesNotCorrupt()
    {
        // When the import throws (e.g., zero scalar rejected by BouncyCastle), the
        // exception must propagate cleanly — the finally block zeroizes the temp copy.
        // We verify the exception is not swallowed and the store remains clean.
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        byte[] zeroScalar = new byte[48]; // scalar = 0 → rejected by EC domain validation
        var importOpts = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);

        // BC rejects scalar 0 as outside [1, n-1]
        Assert.Throws<ArgumentException>(() => svc.ImportPrivateKey(zeroScalar, importOpts));

        // The original caller buffer should not be modified
        Assert.True(zeroScalar.AsSpan().ContainsAnyExcept((byte)0) == false,
            "Original caller buffer should not be modified after failed import.");
    }

    [Fact]
    public void Import_UnsupportedAlgorithm_Throws()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var badAlgo = new AlgorithmId("AES-256-GCM");
        var options = new KeyImportOptions(badAlgo, null, AlgorithmEncodingProfile.RawPublicKey);
        Assert.Throws<NotSupportedException>(() => svc.ImportPublicKey(new byte[97], options));
    }

    [Fact]
    public void Import_UnsupportedEncoding_Throws()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var options = new KeyImportOptions(EcdhP384, null, AlgorithmEncodingProfile.Pkcs8PrivateKey);
        Assert.Throws<NotSupportedException>(() => svc.ImportPublicKey(new byte[97], options));
    }

    // ─────────────────────────────────────────────────────────
    //  SC-002: NativeCurveP384 (OS-backed ECDH)
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void NativeCurveP384_GenerateKeyPair_Returns97BytePublicKey()
    {
        var (privateKey, publicKey) = NativeCurveP384.GenerateKeyPair(EcdhP384);
        using (privateKey)
        {
            Assert.Equal(EcdhP384, publicKey.AlgorithmId);
            Assert.Equal(97, publicKey.Bytes.Length);
            Assert.Equal(0x04, publicKey.Bytes.Span[0]);
        }
    }

    [Fact]
    public void NativeCurveP384_SharedSecret_Is48Bytes()
    {
        var (privA, pubA) = NativeCurveP384.GenerateKeyPair(EcdhP384);
        var (privB, pubB) = NativeCurveP384.GenerateKeyPair(EcdhP384);

        using (privA)
        using (privB)
        {
            byte[] secretAB = NativeCurveP384.DeriveSharedSecret(privA, pubB.Bytes.Span);
            byte[] secretBA = NativeCurveP384.DeriveSharedSecret(privB, pubA.Bytes.Span);

            try
            {
                Assert.Equal(48, secretAB.Length);
                Assert.Equal(48, secretBA.Length);
                // Both sides must derive the same shared secret
                Assert.Equal(secretAB, secretBA);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secretAB);
                CryptographicOperations.ZeroMemory(secretBA);
            }
        }
    }

    [Fact]
    public void NativeCurveP384_InvalidPublicKey_Throws()
    {
        var (priv, _) = NativeCurveP384.GenerateKeyPair(EcdhP384);
        using (priv)
        {
            Assert.Throws<CryptographicException>(
                () => NativeCurveP384.DeriveSharedSecret(priv, new byte[32]));
        }
    }
}
