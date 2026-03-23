using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.Runtime;
using Xunit;

namespace Cybersuite.Tests.Unit.Runtime;

public sealed class RuntimeBindingFactoryTests
{
    [Fact]
    public void CreateEffectiveComplianceContext_PolicyFipsRequiredWithoutForceFips_IsEffectiveFipsTrue()
    {
        IPolicy policy = TestFixtures.Policy()
            .WithFips(true)
            .WithTenant("tenant-a")
            .AllowProvider(TestFixtures.ProviderA)
            .Build();

        var context = new SelectionContext(null, ExecutionProfile.Prod, null);
        EffectiveComplianceContext effective = RuntimeBindingFactory.CreateEffectiveComplianceContext(
            policy,
            context,
            RuntimeOptions.Default);

        Assert.True(effective.PolicyFipsRequired);
        Assert.Null(effective.ForceFips);
        Assert.True(effective.EffectiveFipsRequired);
        Assert.Equal("tenant-a", effective.TenantId);
        Assert.Equal(RequiredBoundaryClass.ValidatedBoundary, effective.RequiredBoundaryClass);
        Assert.Contains(TestFixtures.ProviderA, effective.RequiredProviderIds);
    }

    [Fact]
    public void CreateEffectiveComplianceContext_ForceFipsFalse_OverridesPolicyRequirement()
    {
        IPolicy policy = TestFixtures.Policy()
            .WithFips(true)
            .Build();

        var context = new SelectionContext(null, ExecutionProfile.Dev, false);
        EffectiveComplianceContext effective = RuntimeBindingFactory.CreateEffectiveComplianceContext(
            policy,
            context,
            RuntimeOptions.Default);

        Assert.False(effective.EffectiveFipsRequired);
        Assert.Equal(RequiredBoundaryClass.None, effective.RequiredBoundaryClass);
    }

    [Fact]
    public void Create_BindsEffectiveComplianceIntoProviderSessionBinding()
    {
        IPolicy policy = TestFixtures.Policy()
            .WithFips(false)
            .AllowProvider(TestFixtures.ProviderA)
            .PinCategory(AlgorithmCategory.Signature, TestFixtures.ProviderB)
            .Build();

        var context = new SelectionContext("tenant-b", ExecutionProfile.Staging, null);
        global::Cybersuite.ProviderHost.ProviderSessionBinding binding = RuntimeBindingFactory.Create(
            policy,
            context,
            RuntimeOptions.Default);

        Assert.NotNull(binding.EffectiveCompliance);
        Assert.Equal(ExecutionProfile.Staging, binding.EffectiveCompliance!.Profile);
        Assert.Equal(RequiredBoundaryClass.IsolatedProcess, binding.EffectiveCompliance.RequiredBoundaryClass);
        Assert.Equal("tenant-b", binding.EffectiveCompliance.TenantId);
        Assert.Contains(TestFixtures.ProviderA, binding.EffectiveCompliance.RequiredProviderIds);
        Assert.Contains(TestFixtures.ProviderB, binding.EffectiveCompliance.RequiredProviderIds);
        Assert.True(binding.PolicyHashSha384.AsSpan().SequenceEqual(binding.EffectiveCompliance.PolicyHashSha384.AsSpan()));
    }
}
