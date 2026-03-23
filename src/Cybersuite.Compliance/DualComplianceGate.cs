using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Compliance;

/// <summary>
/// Dual gate:
/// 1) algorithm approval
/// 2) provider boundary/module approval
/// </summary>
public sealed class DualComplianceGate : IComplianceGate
{
    private readonly ComplianceOptions _options;

    public DualComplianceGate(ComplianceOptions? options = null)
    {
        _options = options ?? ComplianceOptions.Default;
    }

    public ComplianceDecision Evaluate(
        AlgorithmDescriptor descriptor,
        ProviderMetadata providerMetadata,
        bool providerFipsBoundaryDeclared,
        in ComplianceEvaluationContext context)
    {
        bool experimentalAllowed = _options.IsExperimentalAllowed(context.Profile);
        RequiredBoundaryClass requiredBoundaryClass = context.FipsRequired
            ? RequiredBoundaryClass.ValidatedBoundary
            : RequiredBoundaryClass.None;

        return EvaluateCore(
            descriptor,
            providerMetadata,
            providerFipsBoundaryDeclared,
            context.FipsRequired,
            experimentalAllowed,
            requiredBoundaryClass);
    }

    public ComplianceDecision Evaluate(
        AlgorithmDescriptor descriptor,
        ProviderMetadata providerMetadata,
        in EffectiveComplianceContext context)
    {
        return EvaluateCore(
            descriptor,
            providerMetadata,
            providerMetadata.ComplianceEnvelope.DeclaredValidatedBoundary ||
                providerMetadata.ComplianceProfile.DeclaredValidatedBoundary,
            context.EffectiveFipsRequired,
            context.ExperimentalAllowed,
            context.RequiredBoundaryClass);
    }

    private ComplianceDecision EvaluateCore(
        AlgorithmDescriptor descriptor,
        ProviderMetadata providerMetadata,
        bool providerFipsBoundaryDeclared,
        bool fipsRequired,
        bool experimentalAllowed,
        RequiredBoundaryClass requiredBoundaryClass)
    {
        if (descriptor.OperationalMaturity == AlgorithmOperationalMaturity.Deprecated)
        {
            return new ComplianceDecision(false, "Deprecated algorithm capability is not allowed.");
        }

        if (descriptor.OperationalMaturity == AlgorithmOperationalMaturity.Experimental && !experimentalAllowed)
        {
            return new ComplianceDecision(false, "Experimental algorithm capability is not allowed in this execution profile.");
        }

        if (!fipsRequired)
        {
            if (_options.EnforceRequiredBoundaryClassOutsideFips &&
                requiredBoundaryClass != RequiredBoundaryClass.None &&
                !BoundarySatisfies(providerMetadata.ComplianceEnvelope.BoundaryClass, requiredBoundaryClass))
            {
                return new ComplianceDecision(false, "Provider boundary class does not satisfy the required runtime boundary class.");
            }

            return new ComplianceDecision(true, "Allowed.");
        }

        if (!descriptor.IsFipsApproved)
        {
            return new ComplianceDecision(false, "Algorithm is not FIPS-approved.");
        }

        if (!providerFipsBoundaryDeclared)
        {
            return new ComplianceDecision(false, "Provider did not declare a FIPS boundary.");
        }

        if (_options.RequireValidatedBoundaryWhenFips &&
            !providerMetadata.ComplianceProfile.DeclaredValidatedBoundary)
        {
            return new ComplianceDecision(false, "Provider compliance profile does not declare a validated boundary.");
        }

        if (!BoundarySatisfies(providerMetadata.ComplianceEnvelope.BoundaryClass, RequiredBoundaryClass.ValidatedBoundary))
        {
            return new ComplianceDecision(false, "Provider boundary class does not satisfy the required validated boundary.");
        }

        return new ComplianceDecision(true, "Allowed under dual compliance gate.");
    }

    private static bool BoundarySatisfies(
        RequiredBoundaryClass actual,
        RequiredBoundaryClass required)
        => (int)actual >= (int)required;
}
