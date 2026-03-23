using System.Text;
using Cybersuite.Abstractions;
using Cybersuite.Policy;
using Xunit;

namespace Cybersuite.Tests.Unit.Policy;

public sealed class PolicyWave5Tests
{
    [Fact]
    public void CreateDevelopmentPqm_ReturnsPqcPolicyPinnedToBouncyCastle()
    {
        PolicySnapshot policy = PolicyDefaults.CreateDevelopmentPqm();

        Assert.Equal(PolicySecurityMode.Pqc, policy.SecurityMode);
        Assert.False(policy.FipsRequired);
        Assert.Single(policy.ProviderAllowlist);
        Assert.Contains(new ProviderId("BouncyCastle"), policy.ProviderAllowlist);
        Assert.Equal(new ProviderId("BouncyCastle"), policy.PinnedProviderByAlgorithm[new AlgorithmId("ML-KEM-768")]);
        Assert.Equal(new ProviderId("BouncyCastle"), policy.PinnedProviderByAlgorithm[new AlgorithmId("ML-DSA-65")]);
        Assert.Equal(48, policy.PolicyHash.Length);
    }

    [Fact]
    public void CreateDevelopmentPqmJsonTemplate_LoadsViaPolicyLoader()
    {
        byte[] json = PolicyDefaults.CreateDevelopmentPqmJsonTemplate();

        PolicySnapshot policy = PolicyLoader.LoadFromBytes(
            json,
            PolicyLoadOptions.CreateDevRelaxed(requireProviderAllowlist: true));

        Assert.Equal(PolicySecurityMode.Pqc, policy.SecurityMode);
        Assert.Contains(new ProviderId("BouncyCastle"), policy.ProviderAllowlist);
        Assert.Equal("Development", policy.TenantId);
        Assert.Equal(48, policy.PolicyHash.Length);
    }

    [Fact]
    public void SamplePolicy_DefaultsToDevelopmentPqmShape()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "policies", "sample.policy.json");
        string fullPath = Path.GetFullPath(path);
        string json = File.ReadAllText(fullPath, Encoding.UTF8);

        PolicySnapshot policy = PolicyLoader.LoadFromBytes(
            Encoding.UTF8.GetBytes(json),
            PolicyLoadOptions.CreateDevRelaxed(requireProviderAllowlist: true));

        Assert.Equal(PolicySecurityMode.Pqc, policy.SecurityMode);
        Assert.Contains(new ProviderId("BouncyCastle"), policy.ProviderAllowlist);
        Assert.Equal(new ProviderId("BouncyCastle"), policy.PinnedProviderByAlgorithm[new AlgorithmId("ML-KEM-768")]);
    }
}
