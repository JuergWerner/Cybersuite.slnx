namespace Cybersuite.ProviderModel;

/// <summary>
/// Result of provider provenance evaluation.
/// Values distinguish between missing, structurally validated, and rejected bundles
/// without overstating cryptographic release provenance that is not yet implemented.
/// </summary>
public enum ProviderProvenanceStatus
{
    /// <summary>No provenance evaluation was requested or applicable (e.g. Dev profile).</summary>
    None = 0,

    /// <summary>Provenance evaluation was skipped (e.g. verifier returned without checking).</summary>
    NotEvaluated = 1,

    /// <summary>Structured provenance bundle was present and passed all validation gates.</summary>
    StructuredValidated = 2,

    /// <summary>Provenance bundle was expected but not found in the provider package.</summary>
    Missing = 3,

    /// <summary>Provenance bundle was present but failed validation (hash mismatch, expired, etc.).</summary>
    Rejected = 4
}
