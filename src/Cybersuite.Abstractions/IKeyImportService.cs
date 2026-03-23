using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Explicit import contract for interoperable key material.
/// Import is provider-bound and may be restricted by policy/compliance profile.
/// 
/// This interface is additive and not yet wired into Runtime/ProviderHost orchestration.
/// A provider may implement it in a later stage without changing the current control flow.
/// </summary>
public interface IKeyImportService : ICryptoService
{
    /// <summary>
    /// Imports an encoded public key into the provider. The returned <see cref="PublicKey"/> is
    /// bound to the algorithm specified in <paramref name="options"/>.
    /// </summary>
    /// <param name="encodedPublicKey">Raw or ASN.1-encoded public key bytes.</param>
    /// <param name="options">Import options specifying algorithm, parameter set, and encoding profile.</param>
    /// <returns>A provider-bound public key value.</returns>
    PublicKey ImportPublicKey(
        ReadOnlySpan<byte> encodedPublicKey,
        in KeyImportOptions options);

    /// <summary>
    /// Imports an encoded private key into the provider’s secure key store.
    /// The returned <see cref="PrivateKeyHandle"/> is an opaque reference — the raw bytes
    /// are consumed and should be zeroized by the caller after import.
    /// </summary>
    /// <param name="encodedPrivateKey">Raw or ASN.1-encoded private key bytes.</param>
    /// <param name="options">Import options specifying algorithm, parameter set, and encoding profile.</param>
    /// <returns>An opaque handle to the imported private key inside the provider boundary.</returns>
    PrivateKeyHandle ImportPrivateKey(
        ReadOnlySpan<byte> encodedPrivateKey,
        in KeyImportOptions options);
}