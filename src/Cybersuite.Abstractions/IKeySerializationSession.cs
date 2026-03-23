namespace Cybersuite.Abstractions;

/// <summary>
/// Optional extension session for providers that support import/export.
/// This does NOT change the existing IProviderSession contract and therefore does not break the current build.
/// Runtime or higher layers can detect/support this capability later via safe casting.
/// </summary>
public interface IKeySerializationSession : IProviderSession
{
    /// <summary>
    /// Returns a key import service for the specified algorithm.
    /// Allows importing external key material into the provider’s secure store.
    /// </summary>
    /// <param name="algorithmId">The algorithm for which to obtain the import service.</param>
    /// <returns>A provider-bound key import service.</returns>
    IKeyImportService GetKeyImport(AlgorithmId algorithmId);

    /// <summary>
    /// Returns a key export service for the specified algorithm.
    /// Allows exporting key material from the provider (may be rejected for private keys by policy).
    /// </summary>
    /// <param name="algorithmId">The algorithm for which to obtain the export service.</param>
    /// <returns>A provider-bound key export service.</returns>
    IKeyExportService GetKeyExport(AlgorithmId algorithmId);
}