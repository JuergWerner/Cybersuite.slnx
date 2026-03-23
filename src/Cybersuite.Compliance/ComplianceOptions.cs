using Cybersuite.Abstractions;

namespace Cybersuite.Compliance;

/// <summary>
/// Compliance behavior knobs. Immutable and thread-safe.
/// Wave 1 introduces a canonical effective compliance context. Boundary enforcement for
/// non-FIPS IsolatedProcess profiles remains opt-in until the later host/boundary waves land.
/// </summary>
public sealed record ComplianceOptions
{
    public bool AllowExperimentalInDev { get; init; } = true;
    public bool AllowExperimentalInStaging { get; init; } = false;
    public bool AllowExperimentalInProd { get; init; } = false;

    /// <summary>
    /// If FIPS is required, the gate requires both descriptor approval and a validated provider boundary.
    /// </summary>
    public bool RequireValidatedBoundaryWhenFips { get; init; } = true;

    /// <summary>
    /// Future-facing switch for enforcing non-FIPS profile boundary classes such as IsolatedProcess.
    /// Wave 1 keeps this disabled by default to scope the implementation to the compliance truth chain.
    /// </summary>
    public bool EnforceRequiredBoundaryClassOutsideFips { get; init; } = false;

    public static ComplianceOptions Default { get; } = new();

    public bool IsExperimentalAllowed(ExecutionProfile profile)
        => profile switch
        {
            ExecutionProfile.Dev => AllowExperimentalInDev,
            ExecutionProfile.Staging => AllowExperimentalInStaging,
            ExecutionProfile.Prod => AllowExperimentalInProd,
            _ => false
        };
}
