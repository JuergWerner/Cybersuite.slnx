using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Compliance;

/// <summary>
/// Bridges the legacy compliance interface to the Wave 1 canonical effective compliance context.
/// </summary>
public static class ComplianceGateExtensions
{
    public static ComplianceDecision Evaluate(
        this IComplianceGate gate,
        AlgorithmDescriptor descriptor,
        ProviderMetadata providerMetadata,
        in EffectiveComplianceContext context)
    {
        ArgumentNullException.ThrowIfNull(gate);
        ArgumentNullException.ThrowIfNull(providerMetadata);

        if (gate is DualComplianceGate dualGate)
            return dualGate.Evaluate(descriptor, providerMetadata, in context);

        var legacyContext = new ComplianceEvaluationContext(
            Profile: context.Profile,
            FipsRequired: context.EffectiveFipsRequired);

        bool providerFipsBoundaryDeclared =
            providerMetadata.ComplianceEnvelope.DeclaredValidatedBoundary ||
            providerMetadata.ComplianceProfile.DeclaredValidatedBoundary;

        return gate.Evaluate(descriptor, providerMetadata, providerFipsBoundaryDeclared, in legacyContext);
    }
}
