using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Compliance;

public sealed class AllowAllComplianceGate : IComplianceGate
{
    public static AllowAllComplianceGate Instance { get; } = new();

    private AllowAllComplianceGate() { }

    public ComplianceDecision Evaluate(
        AlgorithmDescriptor descriptor,
        ProviderMetadata providerMetadata,
        bool providerFipsBoundaryDeclared,
        in ComplianceEvaluationContext context)
        => new(true, "Allowed.");
}