using Cybersuite.Abstractions;

namespace Cybersuite.Runtime;

/// <summary>
/// Runtime-facing immutable selection plan entry.
/// </summary>
public sealed record RuntimeSelectionPlanEntry
{
    public required AlgorithmCategory Category { get; init; }
    public required AlgorithmId AlgorithmId { get; init; }
    public required ProviderId ProviderId { get; init; }

    public required AlgorithmSecurityMode SecurityMode { get; init; }
    public required SecurityStrength Strength { get; init; }
    public HybridSecurityStrength? HybridStrength { get; init; }

    public required bool IsFipsApproved { get; init; }

    public AlgorithmParameterSetId? ParameterSetId { get; init; }
    public AlgorithmOperationalMaturity OperationalMaturity { get; init; }
    public AlgorithmEncodingProfile EncodingProfile { get; init; }

    public required string ProviderVersion { get; init; }
    public required bool ProviderIsExperimental { get; init; }
    public required bool ProviderFipsBoundaryDeclared { get; init; }
}