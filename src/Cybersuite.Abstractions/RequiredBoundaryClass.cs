namespace Cybersuite.Abstractions;

/// <summary>
/// Canonical minimum boundary requirement derived from the effective compliance posture.
/// The value is computed once and then re-used consistently by runtime selection,
/// provider admission, and session opening.
/// </summary>
public enum RequiredBoundaryClass
{
    /// <summary>No boundary requirement. Dev profile typically uses this. Providers may run in-process.</summary>
    None = 0,

    /// <summary>
    /// Provider must execute in an isolated process (OOP). The ProviderHost enforces that
    /// <see cref="ProviderModel.ProviderIsolationMode.ProductionIsolated"/> providers run in a
    /// separate worker process with structured provenance and attestation verification.
    /// </summary>
    IsolatedProcess = 1,

    /// <summary>
    /// Provider must execute within a validated cryptographic boundary (e.g. FIPS 140-3 module).
    /// This level is currently planned but not yet implemented — selection fail-closes if required.
    /// </summary>
    ValidatedBoundary = 2
}
