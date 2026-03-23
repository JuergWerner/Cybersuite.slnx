namespace Cybersuite.Abstractions;

/// <summary>
/// Explicit export contract for interoperable key material.
/// Export is intentionally explicit because it may cross the provider boundary.
/// Providers may reject private-key export fail-closed.
/// </summary>
public interface IKeyExportService : ICryptoService
{
    byte[] ExportPublicKey(
        in PublicKey publicKey,
        in KeyExportOptions options);

    /// <summary>
    /// Exports a private key as raw bytes. The caller MUST zeroize the returned array.
    /// Prefer <see cref="ExportPrivateKeySecure"/> which auto-zeroizes on dispose.
    /// </summary>
    byte[] ExportPrivateKey(
        PrivateKeyHandle privateKey,
        in KeyExportOptions options);

    /// <summary>
    /// Exports a private key wrapped in <see cref="SecretBytes"/> that auto-zeroizes on dispose.
    /// This is the recommended method for private key export.
    /// </summary>
    SecretBytes ExportPrivateKeySecure(
        PrivateKeyHandle privateKey,
        in KeyExportOptions options);
}