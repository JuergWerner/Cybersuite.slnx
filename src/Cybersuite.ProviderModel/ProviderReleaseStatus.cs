namespace Cybersuite.ProviderModel;

/// <summary>
/// Result of structured release-bundle evaluation.
/// Wave 5 uses this to distinguish between missing, structurally validated,
/// and rejected source-release metadata without overclaiming a full external CI pipeline.
/// </summary>
public enum ProviderReleaseStatus
{
    /// <summary>No release evaluation was requested or applicable (e.g. Dev profile).</summary>
    None = 0,

    /// <summary>Release evaluation was skipped (e.g. verifier returned without checking).</summary>
    NotEvaluated = 1,

    /// <summary>Structured release bundle was present and passed all validation gates (Wave 5).</summary>
    StructuredValidated = 2,

    /// <summary>Release bundle was expected (non-Dev profile) but not found in the provider package.</summary>
    Missing = 3,

    /// <summary>Release bundle was present but failed validation (version mismatch, expired, invalid digests, etc.).</summary>
    Rejected = 4
}
