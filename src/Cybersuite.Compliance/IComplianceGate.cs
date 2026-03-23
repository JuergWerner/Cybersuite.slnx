using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Compliance;

public interface IComplianceGate
{
    ComplianceDecision Evaluate(
        AlgorithmDescriptor descriptor,
        ProviderMetadata providerMetadata,
        bool providerFipsBoundaryDeclared,
        in ComplianceEvaluationContext context);
}