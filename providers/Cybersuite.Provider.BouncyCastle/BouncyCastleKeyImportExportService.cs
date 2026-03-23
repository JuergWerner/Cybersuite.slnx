using System;
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// USA-001: Reference implementation of <see cref="IKeyImportService"/> and
/// <see cref="IKeyExportService"/> for the BouncyCastle in-process provider.
/// 
/// Supports classical ECDH/ECDSA P-384 keys in <see cref="AlgorithmEncodingProfile.RawPublicKey"/>
/// and <see cref="AlgorithmEncodingProfile.RawPrivateKey"/> encodings.
/// 
/// Security invariants:
/// - The temporary byte[] copy of the private key scalar is zeroized after import (best effort —
///   BigInteger and ECPrivateKeyParameters may retain internal managed-heap copies).
/// - Export of private keys returns a copy; caller is responsible for zeroization.
/// - Unsupported algorithm/encoding combinations are rejected fail-closed.
/// </summary>
public sealed class BouncyCastleKeyImportExportService : IKeyImportService, IKeyExportService
{
    private readonly BouncyCastleKeyMaterialStore _store;
    private readonly ProviderId _providerId;

    public ProviderId ProviderId => _providerId;
    public AlgorithmId AlgorithmId => new("ECDH-P384-KEM"); // primary; also supports ECDSA-P384
    public AlgorithmCategory Category => AlgorithmCategory.KeyEncapsulation;

    internal BouncyCastleKeyImportExportService(
        BouncyCastleKeyMaterialStore store,
        ProviderId providerId)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _providerId = providerId;
    }

    // ──────────────────────────────────────────────────────
    //  IKeyImportService
    // ──────────────────────────────────────────────────────

    /// <summary>
    /// Imports a public key from its encoded form.
    /// Supported encodings: <see cref="AlgorithmEncodingProfile.RawPublicKey"/> (uncompressed EC point, 97 bytes for P-384).
    /// </summary>
    public PublicKey ImportPublicKey(ReadOnlySpan<byte> encodedPublicKey, in KeyImportOptions options)
    {
        ValidateP384Algorithm(options.AlgorithmId);
        RequireEncoding(options.EncodingProfile, AlgorithmEncodingProfile.RawPublicKey);

        if (encodedPublicKey.Length != BouncyCastleCurveP384.PublicKeySizeBytes)
            throw new ArgumentException(
                $"Expected {BouncyCastleCurveP384.PublicKeySizeBytes}-byte uncompressed EC point.",
                nameof(encodedPublicKey));

        // Validate the point is on the curve (BouncyCastle does this in DecodePoint)
        _ = BouncyCastleCurveP384.ParsePublicKey(encodedPublicKey);

        return new PublicKey(options.AlgorithmId, encodedPublicKey.ToArray());
    }

    /// <summary>
    /// Imports a private key (raw 48-byte scalar for P-384) into the provider key store.
    /// The input bytes are NOT retained; they are copied into a BouncyCastle ECPrivateKeyParameters
    /// object and the caller should zeroize the source buffer.
    /// The temporary byte[] copy required by BigInteger is zeroized in a finally block (best effort —
    /// BigInteger itself may retain internal copies on the managed heap).
    /// </summary>
    public PrivateKeyHandle ImportPrivateKey(ReadOnlySpan<byte> encodedPrivateKey, in KeyImportOptions options)
    {
        ValidateP384Algorithm(options.AlgorithmId);
        RequireEncoding(options.EncodingProfile, AlgorithmEncodingProfile.RawPrivateKey);

        if (encodedPrivateKey.Length != BouncyCastleCurveP384.CoordinateSizeBytes)
            throw new ArgumentException(
                $"Expected {BouncyCastleCurveP384.CoordinateSizeBytes}-byte raw private scalar.",
                nameof(encodedPrivateKey));

        // F4-FIX: Copy into a local buffer so we can zeroize it after BigInteger consumes it.
        byte[] tempScalar = encodedPrivateKey.ToArray();
        try
        {
            var d = new BigInteger(1, tempScalar);
            var privateKey = new ECPrivateKeyParameters(d, BouncyCastleCurveP384.Domain);
            return _store.AddPrivateKey(_providerId, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tempScalar);
        }
    }

    // ──────────────────────────────────────────────────────
    //  IKeyExportService
    // ──────────────────────────────────────────────────────

    /// <summary>
    /// Exports a public key as raw uncompressed EC point bytes (97 bytes for P-384).
    /// </summary>
    public byte[] ExportPublicKey(in PublicKey publicKey, in KeyExportOptions options)
    {
        ValidateP384Algorithm(options.AlgorithmId);
        RequireEncoding(options.EncodingProfile, AlgorithmEncodingProfile.RawPublicKey);

        if (publicKey.Bytes.IsEmpty)
            throw new InvalidOperationException("PublicKey has no encoded bytes.");

        return publicKey.Bytes.ToArray();
    }

    /// <summary>
    /// Exports a private key as raw 48-byte scalar.
    /// F6-FIX: The export is gated by the <see cref="KeyExportPolicy"/> in the options.
    /// WARNING: The returned byte array contains secret material. The caller MUST
    /// zeroize it after use (e.g., via <c>CryptographicOperations.ZeroMemory</c>).
    /// Prefer <see cref="ExportPrivateKeySecure"/> for automatic zeroization.
    /// </summary>
    public byte[] ExportPrivateKey(PrivateKeyHandle privateKey, in KeyExportOptions options)
    {
        ValidateP384Algorithm(options.AlgorithmId);
        RequireEncoding(options.EncodingProfile, AlgorithmEncodingProfile.RawPrivateKey);
        EnforceExportPolicy(options.ExportPolicy);

        var ecKey = _store.GetEcPrivateKey(privateKey);
        return ecKey.D.ToByteArrayUnsigned();
    }

    /// <summary>
    /// SEC-V2-002: Exports a private key wrapped in <see cref="Abstractions.SecretBytes"/>
    /// that auto-zeroizes the secret material on dispose.
    /// </summary>
    public Abstractions.SecretBytes ExportPrivateKeySecure(PrivateKeyHandle privateKey, in KeyExportOptions options)
    {
        byte[] raw = ExportPrivateKey(privateKey, options);
        return new Abstractions.SecretBytes(raw);
    }

    // ──────────────────────────────────────────────────────
    //  Validation helpers
    // ──────────────────────────────────────────────────────

    private static void ValidateP384Algorithm(AlgorithmId algorithmId)
    {
        string id = algorithmId.Value;
        if (!string.Equals(id, "ECDH-P384-KEM", StringComparison.Ordinal) &&
            !string.Equals(id, "ECDSA-P384", StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"BouncyCastleKeyImportExportService only supports ECDH-P384-KEM and ECDSA-P384. Got: '{id}'.");
        }
    }

    private static void RequireEncoding(AlgorithmEncodingProfile actual, AlgorithmEncodingProfile expected)
    {
        if (actual != expected)
            throw new NotSupportedException(
                $"Encoding profile '{actual}' is not supported. Expected: '{expected}'.");
    }

    /// <summary>
    /// F6-FIX: Enforces the <see cref="KeyExportPolicy"/> for private key export operations.
    /// </summary>
    private static void EnforceExportPolicy(KeyExportPolicy policy)
    {
        switch (policy)
        {
            case KeyExportPolicy.AllowExplicit:
                return;

            case KeyExportPolicy.DenyByDefault:
                throw new InvalidOperationException(
                    "Private key export denied by policy (DenyByDefault). An explicit override is required.");

            case KeyExportPolicy.Prohibited:
                throw new InvalidOperationException(
                    "Private key export is unconditionally prohibited by policy.");

            default:
                throw new InvalidOperationException(
                    $"Private key export denied fail-closed: unknown KeyExportPolicy '{policy}'.");
        }
    }

    public void Dispose()
    {
        // No owned resources — the key store is owned by the provider connection.
    }
}
