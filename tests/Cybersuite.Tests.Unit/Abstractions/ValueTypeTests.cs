using Cybersuite.Abstractions;
using Xunit;

namespace Cybersuite.Tests.Unit.Abstractions;

/// <summary>
/// Tests for core value types: AlgorithmId, ProviderId, SecurityStrength, HybridSecurityStrength.
/// Validates constructor guards, value semantics, comparison operators, and equality behavior.
/// </summary>
public sealed class ValueTypeTests
{
    // ?? SecurityStrength ??

    [Fact]
    public void SecurityStrength_ZeroBits_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityStrength(0));

    [Fact]
    public void SecurityStrength_NegativeBits_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(() => new SecurityStrength(-1));

    [Theory]
    [InlineData(128)]
    [InlineData(192)]
    [InlineData(256)]
    public void SecurityStrength_ValidBits_RoundTrips(int bits)
    {
        var s = new SecurityStrength(bits);
        Assert.Equal(bits, s.Bits);
    }

    [Fact]
    public void SecurityStrength_Comparison_HigherBitsIsGreater()
    {
        var s128 = new SecurityStrength(128);
        var s256 = new SecurityStrength(256);
        Assert.True(s256 > s128);
        Assert.True(s128 < s256);
        Assert.True(s128 <= s256);
        Assert.True(s256 >= s128);
        Assert.False(s128 > s256);
    }

    [Fact]
    public void SecurityStrength_Equality_SameBitsAreEqual()
    {
        var a = new SecurityStrength(192);
        var b = new SecurityStrength(192);
        Assert.Equal(a.Bits, b.Bits);
        Assert.Equal(0, a.CompareTo(b));
    }

    // ?? HybridSecurityStrength ??

    [Fact]
    public void HybridSecurityStrength_Effective_ReturnsMinimum()
    {
        var hybrid = new HybridSecurityStrength(
            new SecurityStrength(128),
            new SecurityStrength(192));
        Assert.Equal(128, hybrid.Effective.Bits);
    }

    [Fact]
    public void HybridSecurityStrength_Effective_WhenPqcIsLower_ReturnsPqc()
    {
        var hybrid = new HybridSecurityStrength(
            new SecurityStrength(256),
            new SecurityStrength(128));
        Assert.Equal(128, hybrid.Effective.Bits);
    }

    [Fact]
    public void HybridSecurityStrength_Effective_WhenEqual_ReturnsThat()
    {
        var hybrid = new HybridSecurityStrength(
            new SecurityStrength(192),
            new SecurityStrength(192));
        Assert.Equal(192, hybrid.Effective.Bits);
    }

    // ?? AlgorithmId / ProviderId value semantics ??

    [Fact]
    public void AlgorithmId_Equality_SameValueAreEqual()
    {
        var a = new AlgorithmId("ML-KEM-768");
        var b = new AlgorithmId("ML-KEM-768");
        Assert.Equal(a, b);
        Assert.True(a == b);
    }

    [Fact]
    public void AlgorithmId_Equality_DifferentValuesAreNotEqual()
    {
        var a = new AlgorithmId("ML-KEM-768");
        var b = new AlgorithmId("ML-KEM-512");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ProviderId_Equality_SameValueAreEqual()
    {
        var a = new ProviderId("BC");
        var b = new ProviderId("BC");
        Assert.Equal(a, b);
    }

    [Fact]
    public void AlgorithmId_ToString_ReturnsValue()
        => Assert.Equal("AES-256-GCM", new AlgorithmId("AES-256-GCM").ToString());

    [Fact]
    public void ProviderId_ToString_ReturnsValue()
        => Assert.Equal("TestProvider", new ProviderId("TestProvider").ToString());

    // ?? AlgorithmParameterSetId ??

    [Fact]
    public void AlgorithmParameterSetId_Equality()
    {
        var a = new AlgorithmParameterSetId("ML-KEM-768");
        var b = new AlgorithmParameterSetId("ML-KEM-768");
        Assert.Equal(a, b);
    }

    // ?? Handle types ??

    [Fact]
    public void PrivateKeyHandle_Equality()
    {
        var id = Guid.NewGuid();
        var p = new ProviderId("P");
        var a = new PrivateKeyHandle(p, id);
        var b = new PrivateKeyHandle(p, id);
        Assert.Equal(a, b);
    }

    [Fact]
    public void SecretKeyHandle_DifferentGuids_NotEqual()
    {
        var p = new ProviderId("P");
        var a = new SecretKeyHandle(p, Guid.NewGuid());
        var b = new SecretKeyHandle(p, Guid.NewGuid());
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void SharedSecretHandle_Equality()
    {
        var id = Guid.NewGuid();
        var p = new ProviderId("P");
        Assert.Equal(new SharedSecretHandle(p, id), new SharedSecretHandle(p, id));
    }
}
