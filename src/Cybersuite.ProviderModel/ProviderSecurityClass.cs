namespace Cybersuite.ProviderModel;

/// <summary>
/// Truthful provider security class carried by manifests and handshakes.
/// These values are operational admission labels, not marketing labels.
/// </summary>
public enum ProviderSecurityClass
{
    /// <summary>Reference in-process provider for Dev/testing. No isolation boundary, no production claims.</summary>
    ReferenceInProcess = 0,

    /// <summary>Production-grade isolated provider running in a separate worker process. Structured provenance and attestation apply.</summary>
    ProductionIsolated = 1,

    /// <summary>Validated cryptographic boundary (e.g. FIPS 140-3 certified module). Currently planned, not yet implemented.</summary>
    ValidatedBoundary = 2
}
