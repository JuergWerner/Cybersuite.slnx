using Cybersuite.Abstractions;
using Xunit;

namespace Cybersuite.Tests.Unit.Abstractions;

/// <summary>
/// Tests for AlgorithmDescriptor constructor validation and immutability invariants.
/// Validates all guard clauses per [ARC-030]:
/// - Non-empty AlgorithmId and ProviderId
/// - HybridStrength required iff SecurityMode == Hybrid
/// - ParameterSetId validation
/// - OperationalMaturity and EncodingProfile defaults
/// </summary>
public sealed class AlgorithmDescriptorTests
{
    [Fact]
    public void Constructor_EmptyAlgorithmId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new AlgorithmDescriptor(
            id: new AlgorithmId(""),
            provider: new ProviderId("P"),
            category: AlgorithmCategory.Hash,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(128),
            isFipsApproved: false));
    }

    [Fact]
    public void Constructor_EmptyProviderId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new AlgorithmDescriptor(
            id: new AlgorithmId("SHA-384"),
            provider: new ProviderId(""),
            category: AlgorithmCategory.Hash,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(192),
            isFipsApproved: false));
    }

    [Fact]
    public void Constructor_HybridMode_WithoutHybridStrength_Throws()
    {
        Assert.Throws<ArgumentException>(() => new AlgorithmDescriptor(
            id: new AlgorithmId("HybridKEM"),
            provider: new ProviderId("P"),
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Hybrid,
            strength: new SecurityStrength(128),
            isFipsApproved: false,
            hybridStrength: null));
    }

    [Fact]
    public void Constructor_NonHybridMode_WithHybridStrength_Throws()
    {
        Assert.Throws<ArgumentException>(() => new AlgorithmDescriptor(
            id: new AlgorithmId("ML-KEM-768"),
            provider: new ProviderId("P"),
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Pqc,
            strength: new SecurityStrength(192),
            isFipsApproved: false,
            hybridStrength: new HybridSecurityStrength(
                new SecurityStrength(128),
                new SecurityStrength(192))));
    }

    [Fact]
    public void Constructor_EmptyParameterSetId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new AlgorithmDescriptor(
            id: new AlgorithmId("ML-KEM-768"),
            provider: new ProviderId("P"),
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Pqc,
            strength: new SecurityStrength(192),
            isFipsApproved: false,
            parameterSetId: new AlgorithmParameterSetId("")));
    }

    [Fact]
    public void Constructor_ValidClassical_AllPropertiesSet()
    {
        var d = new AlgorithmDescriptor(
            id: new AlgorithmId("AES-256-GCM"),
            provider: new ProviderId("BC"),
            category: AlgorithmCategory.SymmetricAead,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(256),
            isFipsApproved: false);

        Assert.Equal("AES-256-GCM", d.Id.Value);
        Assert.Equal("BC", d.Provider.Value);
        Assert.Equal(AlgorithmCategory.SymmetricAead, d.Category);
        Assert.Equal(AlgorithmSecurityMode.Classical, d.SecurityMode);
        Assert.Equal(256, d.Strength.Bits);
        Assert.False(d.IsFipsApproved);
        Assert.Null(d.HybridStrength);
        Assert.Null(d.ParameterSetId);
        Assert.Equal(AlgorithmOperationalMaturity.Stable, d.OperationalMaturity);
        Assert.Equal(AlgorithmEncodingProfile.ProviderNative, d.EncodingProfile);
    }

    [Fact]
    public void Constructor_ValidHybrid_HybridStrengthPreserved()
    {
        var hs = new HybridSecurityStrength(new SecurityStrength(128), new SecurityStrength(192));
        var d = new AlgorithmDescriptor(
            id: new AlgorithmId("X25519+ML-KEM-768"),
            provider: new ProviderId("BC"),
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Hybrid,
            strength: new SecurityStrength(128),
            isFipsApproved: false,
            hybridStrength: hs);

        Assert.NotNull(d.HybridStrength);
        Assert.Equal(128, d.HybridStrength!.Value.Classical.Bits);
        Assert.Equal(192, d.HybridStrength!.Value.PostQuantum.Bits);
    }

    [Fact]
    public void Constructor_PqcWithParameterSet_Preserved()
    {
        var d = new AlgorithmDescriptor(
            id: new AlgorithmId("ML-KEM-768"),
            provider: new ProviderId("BC"),
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Pqc,
            strength: new SecurityStrength(192),
            isFipsApproved: false,
            parameterSetId: new AlgorithmParameterSetId("ML-KEM-768"),
            operationalMaturity: AlgorithmOperationalMaturity.Experimental,
            encodingProfile: AlgorithmEncodingProfile.SubjectPublicKeyInfo);

        Assert.Equal("ML-KEM-768", d.ParameterSetId!.Value.Value);
        Assert.Equal(AlgorithmOperationalMaturity.Experimental, d.OperationalMaturity);
        Assert.Equal(AlgorithmEncodingProfile.SubjectPublicKeyInfo, d.EncodingProfile);
    }
}