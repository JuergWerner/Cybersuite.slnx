using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.Compliance;
using Cybersuite.ProviderModel;
using Xunit;

namespace Cybersuite.Tests.Compliance;

/// <summary>
/// Tests for the DualComplianceGate per the Wave 1 compliance truth chain.
/// Validates both the legacy interface and the canonical EffectiveComplianceContext path.
/// </summary>
public sealed class DualComplianceGateTests
{
    private static ProviderIdentity MakeIdentity() =>
        new(new ProviderId("TestProvider"), "1.0", "HASH", null);

    private static ProviderMetadata MakeMeta(
        bool isExperimental = false,
        bool declaredValidatedBoundary = false)
    {
        var compliance = new ProviderComplianceProfile(
            declaredValidatedBoundary, null, null);
        return new ProviderMetadata(
            MakeIdentity(),
            "Vendor",
            ProviderIsolationMode.InProcess,
            ProviderTrustState.Trusted,
            isExperimental,
            compliance);
    }

    private static ProviderMetadata MakeEnvelopeMeta(
        ProviderComplianceEnvelope envelope,
        bool isExperimental = false)
        => new(
            MakeIdentity(),
            "Vendor",
            ProviderIsolationMode.InProcess,
            ProviderTrustState.Trusted,
            isExperimental,
            envelope);

    private static AlgorithmDescriptor MakeDescriptor(
        bool isFipsApproved = false,
        AlgorithmOperationalMaturity maturity = AlgorithmOperationalMaturity.Stable) =>
        new(
            id: new AlgorithmId("AES-256-GCM"),
            provider: new ProviderId("TestProvider"),
            category: AlgorithmCategory.SymmetricAead,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(256),
            isFipsApproved: isFipsApproved,
            operationalMaturity: maturity);

    private static EffectiveComplianceContext MakeEffectiveContext(
        ExecutionProfile profile,
        bool policyFipsRequired,
        bool? forceFips,
        bool experimentalAllowed,
        RequiredBoundaryClass? requiredBoundaryClass = null)
    {
        return new EffectiveComplianceContext(
            profile: profile,
            policyHashSha384: new byte[48],
            tenantId: null,
            policyFipsRequired: policyFipsRequired,
            forceFips: forceFips,
            experimentalAllowed: experimentalAllowed,
            requiredBoundaryClass: requiredBoundaryClass ?? (forceFips ?? policyFipsRequired
                ? RequiredBoundaryClass.ValidatedBoundary
                : RequiredBoundaryClass.None),
            requiredProviderIds: ImmutableHashSet<ProviderId>.Empty,
            requiredBuildHashes: ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
            attestationRequirement: AttestationRequirement.None);
    }

    [Fact]
    public void Evaluate_Deprecated_AlwaysBlocked()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(maturity: AlgorithmOperationalMaturity.Deprecated);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Dev, false);

        var decision = gate.Evaluate(desc, MakeMeta(), false, ctx);
        Assert.False(decision.IsAllowed);
        Assert.Contains("Deprecated", decision.Reason);
    }

    [Fact]
    public void Evaluate_Experimental_AllowedInDev()
    {
        var gate = new DualComplianceGate(new ComplianceOptions { AllowExperimentalInDev = true });
        var desc = MakeDescriptor(maturity: AlgorithmOperationalMaturity.Experimental);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Dev, false);

        var decision = gate.Evaluate(desc, MakeMeta(), false, ctx);
        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void Evaluate_Experimental_BlockedInProd()
    {
        var gate = new DualComplianceGate(new ComplianceOptions { AllowExperimentalInProd = false });
        var desc = MakeDescriptor(maturity: AlgorithmOperationalMaturity.Experimental);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, false);

        var decision = gate.Evaluate(desc, MakeMeta(), false, ctx);
        Assert.False(decision.IsAllowed);
        Assert.Contains("Experimental", decision.Reason);
    }

    [Fact]
    public void Evaluate_Experimental_BlockedInStaging_Default()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(maturity: AlgorithmOperationalMaturity.Experimental);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Staging, false);

        Assert.False(gate.Evaluate(desc, MakeMeta(), false, ctx).IsAllowed);
    }

    [Fact]
    public void Evaluate_NoFips_StableAlgorithm_Allowed()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor();
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, false);

        Assert.True(gate.Evaluate(desc, MakeMeta(), false, ctx).IsAllowed);
    }

    [Fact]
    public void Evaluate_FipsRequired_NotFipsApproved_Blocked()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(isFipsApproved: false);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, true);

        var decision = gate.Evaluate(desc, MakeMeta(), false, ctx);
        Assert.False(decision.IsAllowed);
        Assert.Contains("not FIPS-approved", decision.Reason);
    }

    [Fact]
    public void Evaluate_FipsRequired_FipsApproved_NoBoundary_Blocked()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(isFipsApproved: true);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, true);

        var decision = gate.Evaluate(desc, MakeMeta(), providerFipsBoundaryDeclared: false, ctx);
        Assert.False(decision.IsAllowed);
        Assert.Contains("FIPS boundary", decision.Reason);
    }

    [Fact]
    public void Evaluate_FipsRequired_BoundaryDeclared_NotValidated_Blocked()
    {
        var gate = new DualComplianceGate(new ComplianceOptions
        {
            RequireValidatedBoundaryWhenFips = true
        });
        var desc = MakeDescriptor(isFipsApproved: true);
        var meta = MakeMeta(declaredValidatedBoundary: false);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, true);

        var decision = gate.Evaluate(desc, meta, providerFipsBoundaryDeclared: true, ctx);
        Assert.False(decision.IsAllowed);
        Assert.Contains("validated boundary", decision.Reason);
    }

    [Fact]
    public void Evaluate_FipsRequired_AllGatesPassed_Allowed()
    {
        var gate = new DualComplianceGate(new ComplianceOptions
        {
            RequireValidatedBoundaryWhenFips = true
        });
        var desc = MakeDescriptor(isFipsApproved: true);
        var meta = MakeMeta(declaredValidatedBoundary: true);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, true);

        var decision = gate.Evaluate(desc, meta, providerFipsBoundaryDeclared: true, ctx);
        Assert.True(decision.IsAllowed);
        Assert.Contains("dual compliance gate", decision.Reason);
    }

    [Fact]
    public void Evaluate_EffectiveContext_PolicyOnlyFips_MatchesForcedFipsDecision()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(isFipsApproved: true);
        var envelope = new ProviderComplianceEnvelope(
            securityClass: ProviderSecurityClass.ValidatedBoundary,
            boundaryClass: RequiredBoundaryClass.ValidatedBoundary,
            declaredValidatedBoundary: true,
            declaredModuleName: "Module-A",
            declaredCertificateReference: "CERT-A",
            declaredModuleVersion: "1.0.0",
            supportsNonExportableKeys: true,
            supportsRawSecretEgress: false,
            attestationMode: AttestationMode.None);
        var meta = MakeEnvelopeMeta(envelope);

        var policyOnly = gate.Evaluate(
            desc,
            meta,
            MakeEffectiveContext(
                profile: ExecutionProfile.Prod,
                policyFipsRequired: true,
                forceFips: null,
                experimentalAllowed: false));

        var forced = gate.Evaluate(
            desc,
            meta,
            MakeEffectiveContext(
                profile: ExecutionProfile.Prod,
                policyFipsRequired: false,
                forceFips: true,
                experimentalAllowed: false));

        Assert.Equal(policyOnly.IsAllowed, forced.IsAllowed);
        Assert.Equal(policyOnly.Reason, forced.Reason);
    }

    [Fact]
    public void Evaluate_EffectiveContext_ForceFipsFalse_OverridesPolicyFipsRequired()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(isFipsApproved: false);
        var meta = MakeMeta();

        var decision = gate.Evaluate(
            desc,
            meta,
            MakeEffectiveContext(
                profile: ExecutionProfile.Prod,
                policyFipsRequired: true,
                forceFips: false,
                experimentalAllowed: false,
                requiredBoundaryClass: RequiredBoundaryClass.None));

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void Evaluate_EffectiveContext_ValidatedBoundaryMismatch_Blocked()
    {
        var gate = new DualComplianceGate();
        var desc = MakeDescriptor(isFipsApproved: true);
        var envelope = new ProviderComplianceEnvelope(
            securityClass: ProviderSecurityClass.ReferenceInProcess,
            boundaryClass: RequiredBoundaryClass.None,
            declaredValidatedBoundary: false,
            declaredModuleName: null,
            declaredCertificateReference: null,
            declaredModuleVersion: null,
            supportsNonExportableKeys: false,
            supportsRawSecretEgress: true,
            attestationMode: AttestationMode.None);
        var meta = MakeEnvelopeMeta(envelope);

        var decision = gate.Evaluate(
            desc,
            meta,
            MakeEffectiveContext(
                profile: ExecutionProfile.Prod,
                policyFipsRequired: true,
                forceFips: null,
                experimentalAllowed: false));

        Assert.False(decision.IsAllowed);
        Assert.Contains("FIPS boundary", decision.Reason);
    }

    [Fact]
    public void Evaluate_EffectiveContext_ExperimentalUsesCanonicalContext()
    {
        var gate = new DualComplianceGate(new ComplianceOptions { AllowExperimentalInProd = true });
        var desc = MakeDescriptor(maturity: AlgorithmOperationalMaturity.Experimental);
        var meta = MakeMeta();

        var decision = gate.Evaluate(
            desc,
            meta,
            MakeEffectiveContext(
                profile: ExecutionProfile.Prod,
                policyFipsRequired: false,
                forceFips: null,
                experimentalAllowed: false));

        Assert.False(decision.IsAllowed);
        Assert.Contains("Experimental", decision.Reason);
    }

    [Fact]
    public void AllowAllGate_AlwaysAllowed()
    {
        var desc = MakeDescriptor(maturity: AlgorithmOperationalMaturity.Deprecated);
        var ctx = new ComplianceEvaluationContext(ExecutionProfile.Prod, true);

        var decision = AllowAllComplianceGate.Instance.Evaluate(desc, MakeMeta(), false, ctx);
        Assert.True(decision.IsAllowed);
    }
}

public sealed class ComplianceOptionsTests
{
    [Fact]
    public void Default_DevAllowsExperimental()
        => Assert.True(ComplianceOptions.Default.IsExperimentalAllowed(ExecutionProfile.Dev));

    [Fact]
    public void Default_ProdBlocksExperimental()
        => Assert.False(ComplianceOptions.Default.IsExperimentalAllowed(ExecutionProfile.Prod));

    [Fact]
    public void Default_StagingBlocksExperimental()
        => Assert.False(ComplianceOptions.Default.IsExperimentalAllowed(ExecutionProfile.Staging));

    [Fact]
    public void Default_UnknownProfile_BlocksExperimental()
        => Assert.False(ComplianceOptions.Default.IsExperimentalAllowed((ExecutionProfile)99));

    [Fact]
    public void Default_RequireValidatedBoundary_True()
        => Assert.True(ComplianceOptions.Default.RequireValidatedBoundaryWhenFips);

    [Fact]
    public void Default_NonFipsBoundaryEnforcement_RemainsDisabledInWave1()
        => Assert.False(ComplianceOptions.Default.EnforceRequiredBoundaryClassOutsideFips);
}
