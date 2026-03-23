using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using Cybersuite.Abstractions;
using Cybersuite.Policy;
using Xunit;

namespace Cybersuite.Tests.Unit.Policy;

public sealed class PolicyWave3Tests
{
    [Fact]
    public void CreateProdStrict_RequiresVerifier_AndEnablesStrictDefaults()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyLoadOptions.CreateProdStrict(null!));

        PolicyLoadOptions options = PolicyLoadOptions.CreateProdStrict(new AcceptingVerifier());

        Assert.Equal(ExecutionProfile.Prod, options.Profile);
        Assert.True(options.RequireSignatureVerification);
        Assert.True(options.RequireProviderAllowlist);
        Assert.NotNull(options.SignatureVerifier);
        Assert.Equal(X509RevocationMode.Online, options.SignatureVerificationOptions.RevocationMode);
        Assert.False(options.SignatureVerificationOptions.AllowUntrustedChainInDevOnly);
    }

    [Fact]
    public void ProdCtor_RejectsNoCheckRevocation()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new PolicyLoadOptions(
                profile: ExecutionProfile.Prod,
                requireSignatureVerification: true,
                requireProviderAllowlist: true,
                signatureVerifier: new AcceptingVerifier(),
                signatureVerificationOptions: new PolicySignatureVerificationOptions(
                    trustedRootsDer: ImmutableArray<ReadOnlyMemory<byte>>.Empty,
                    allowedSignerThumbprints: ImmutableHashSet<string>.Empty,
                    allowUntrustedChainInDevOnly: false,
                    revocationMode: X509RevocationMode.NoCheck)));

        Assert.Contains("NoCheck", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void StagingCtor_RejectsAllowUntrustedChainFlag()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new PolicyLoadOptions(
                profile: ExecutionProfile.Staging,
                requireSignatureVerification: true,
                requireProviderAllowlist: true,
                signatureVerifier: new AcceptingVerifier(),
                signatureVerificationOptions: new PolicySignatureVerificationOptions(
                    trustedRootsDer: ImmutableArray<ReadOnlyMemory<byte>>.Empty,
                    allowedSignerThumbprints: ImmutableHashSet<string>.Empty,
                    allowUntrustedChainInDevOnly: true,
                    revocationMode: X509RevocationMode.Online)));

        Assert.Contains("Dev", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ProdCtor_WithoutExplicitStrictOptions_FailsFast()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            new PolicyLoadOptions(
                profile: ExecutionProfile.Prod,
                requireSignatureVerification: true,
                requireProviderAllowlist: true,
                signatureVerifier: new AcceptingVerifier(),
                signatureVerificationOptions: null));

        Assert.Contains("CreateProdStrict", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DevRelaxed_AllowsNoCheck_AndOptionalUntrustedChain()
    {
        PolicyLoadOptions options = PolicyLoadOptions.CreateDevRelaxed(
            signatureVerificationOptions: PolicySignatureVerificationOptions.CreateDevRelaxed(
                allowUntrustedChainInDevOnly: true,
                revocationMode: X509RevocationMode.NoCheck));

        Assert.Equal(ExecutionProfile.Dev, options.Profile);
        Assert.False(options.RequireSignatureVerification);
        Assert.False(options.RequireProviderAllowlist);
        Assert.True(options.SignatureVerificationOptions.AllowUntrustedChainInDevOnly);
        Assert.Equal(X509RevocationMode.NoCheck, options.SignatureVerificationOptions.RevocationMode);
    }

    private sealed class AcceptingVerifier : IPolicySignatureVerifier
    {
        public bool Verify(
            ReadOnlySpan<byte> canonicalPolicyBytes,
            PolicySignatureEnvelope signature,
            PolicySignatureVerificationOptions options,
            out string? failureReason)
        {
            failureReason = null;
            return true;
        }
    }
}
