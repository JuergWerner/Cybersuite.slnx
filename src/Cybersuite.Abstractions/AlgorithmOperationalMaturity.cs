namespace Cybersuite.Abstractions;

/// <summary>
/// Operational maturity of a provider-exposed algorithm capability.
/// This is orthogonal to security mode and FIPS status.
/// </summary>
public enum AlgorithmOperationalMaturity
{
    /// <summary>Production-ready capability. Selected by default unless policy overrides.</summary>
    Stable = 0,

    /// <summary>
    /// Experimental capability (e.g. PQC algorithms on beta BouncyCastle).
    /// Only admitted when <see cref="EffectiveComplianceContext.ExperimentalAllowed"/> is true.
    /// The Dev execution profile allows experimental capabilities; Staging and Prod reject them fail-closed.
    /// </summary>
    Experimental = 1,

    /// <summary>Deprecated capability scheduled for removal. Selection engine may warn or reject depending on policy.</summary>
    Deprecated = 2
}