using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.Selection;
using Xunit;

namespace Cybersuite.Tests.Unit.Selection;

/// <summary>
/// Tests for the deterministic, fail-closed AlgorithmSelector per [SEL-000].
/// Covers: strength filtering, mode enforcement (anti-downgrade), FIPS gating,
/// provider allowlist, pinning (category + algorithm), deterministic tie-breaking,
/// and fail-closed behavior when no candidate exists.
/// </summary>
public sealed class AlgorithmSelectorTests
{
    private readonly AlgorithmSelector _selector = new();

    // ?? Basic selection: meets minimum strength ??

    [Fact]
    public void Select_SingleCategory_PicksOnlyCandidate()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.SymmetricAead, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Aead(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);

        Assert.Single(result);
        Assert.Equal("AES-256-GCM", result[AlgorithmCategory.SymmetricAead].Id.Value);
    }

    // ?? Strength filtering: below minimum rejected ??

    [Fact]
    public void Select_BelowMinStrength_FailsClosed()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 256) // requires 256, SHA-384 has 192
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Hash(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        Assert.Throws<SelectionFailedException>(() => _selector.Select(policy, caps, in ctx));
    }

    // ?? Mode enforcement: anti-downgrade invariant ??

    [Fact]
    public void Select_PqcPolicy_RejectsClassicalKEM()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Pqc)
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .Build();

        // Only classical KEM available — must fail
        var caps = ImmutableArray.Create(TestFixtures.Classical_KEM(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var ex = Assert.Throws<SelectionFailedException>(() => _selector.Select(policy, caps, in ctx));
        Assert.Equal(AlgorithmCategory.KeyEncapsulation, ex.Category);
    }

    [Fact]
    public void Select_PqcPolicy_AcceptsPqcKEM()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Pqc)
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Pqc_KEM(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("ML-KEM-768", result[AlgorithmCategory.KeyEncapsulation].Id.Value);
    }

    [Fact]
    public void Select_ClassicalPolicy_RejectsPqcSignature()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Signature, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Pqc_Sig(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        Assert.Throws<SelectionFailedException>(() => _selector.Select(policy, caps, in ctx));
    }

    [Fact]
    public void Select_HybridPolicy_AcceptsHybridKEM()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Hybrid)
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Hybrid_KEM(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal(AlgorithmSecurityMode.Hybrid, result[AlgorithmCategory.KeyEncapsulation].SecurityMode);
    }

    // ?? Mode not enforced for symmetric categories ??

    [Fact]
    public void Select_PqcPolicy_AcceptsClassicalAead()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Pqc)
            .RequireCategory(AlgorithmCategory.SymmetricAead, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Aead(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("AES-256-GCM", result[AlgorithmCategory.SymmetricAead].Id.Value);
    }

    // ?? FIPS gating ??

    [Fact]
    public void Select_FipsRequired_RejectsNonFipsAlgorithm()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .WithFips()
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Classical_KEM(TestFixtures.ProviderA)); // IsFipsApproved=false
        var ctx = new SelectionContext(null, ExecutionProfile.Prod, null);

        Assert.Throws<SelectionFailedException>(() => _selector.Select(policy, caps, in ctx));
    }

    [Fact]
    public void Select_FipsRequired_AcceptsFipsAlgorithm()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .WithFips()
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Fips_KEM(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Prod, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.True(result[AlgorithmCategory.KeyEncapsulation].IsFipsApproved);
    }

    [Fact]
    public void Select_ForceFipsOverridesPolicy()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .WithFips(false) // policy says no FIPS
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Classical_KEM(TestFixtures.ProviderA)); // non-FIPS
        var ctx = new SelectionContext(null, ExecutionProfile.Prod, true); // context forces FIPS

        Assert.Throws<SelectionFailedException>(() => _selector.Select(policy, caps, in ctx));
    }

    // ?? Provider allowlist ??

    [Fact]
    public void Select_AllowlistExcludes_UnlistedProvider()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .AllowProvider(TestFixtures.ProviderB) // only B allowed
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Hash(TestFixtures.ProviderA)); // A not allowed
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        Assert.Throws<SelectionFailedException>(() => _selector.Select(policy, caps, in ctx));
    }

    [Fact]
    public void Select_AllowlistIncludes_ListedProvider()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .AllowProvider(TestFixtures.ProviderA)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Hash(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("ProviderA", result[AlgorithmCategory.Hash].Provider.Value);
    }

    // ?? Pinning: category-level ??

    [Fact]
    public void Select_CategoryPin_SelectsPinnedProvider()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .PinCategory(AlgorithmCategory.Hash, TestFixtures.ProviderB)
            .Build();

        var caps = ImmutableArray.Create(
            TestFixtures.Hash(TestFixtures.ProviderA),
            TestFixtures.Hash(TestFixtures.ProviderB));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("ProviderB", result[AlgorithmCategory.Hash].Provider.Value);
    }

    // ?? Pinning: algorithm-level overrides category-level ??

    [Fact]
    public void Select_AlgorithmPin_OverridesCategoryPin()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .PinCategory(AlgorithmCategory.Hash, TestFixtures.ProviderA) // category pin to A
            .PinAlgorithm(TestFixtures.Sha384, TestFixtures.ProviderB) // algorithm pin to B
            .Build();

        var caps = ImmutableArray.Create(
            TestFixtures.Hash(TestFixtures.ProviderA),
            TestFixtures.Hash(TestFixtures.ProviderB));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("ProviderB", result[AlgorithmCategory.Hash].Provider.Value);
    }

    // ?? Deterministic tie-breaking ??

    [Fact]
    public void Select_SameStrength_DeterministicByProviderThenAlgorithmId()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .Build();

        // Both 192-bit, providers are "AAA" and "ZZZ" — AAA should win
        var caps = ImmutableArray.Create(
            TestFixtures.Hash(new ProviderId("ZZZ")),
            TestFixtures.Hash(new ProviderId("AAA")));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("AAA", result[AlgorithmCategory.Hash].Provider.Value);
    }

    [Fact]
    public void Select_HigherStrength_WinsOverLexicographic()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .Build();

        var caps = ImmutableArray.Create(
            TestFixtures.Hash(new ProviderId("AAA"), 192),
            TestFixtures.Hash(new ProviderId("ZZZ"), 256));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal("ZZZ", result[AlgorithmCategory.Hash].Provider.Value);
        Assert.Equal(256, result[AlgorithmCategory.Hash].Strength.Bits);
    }

    // ?? Multiple categories ??

    [Fact]
    public void Select_MultipleCategories_EachResolved()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.KeyEncapsulation, 128)
            .RequireCategory(AlgorithmCategory.Signature, 128)
            .RequireCategory(AlgorithmCategory.SymmetricAead, 128)
            .RequireCategory(AlgorithmCategory.KeyDerivation, 128)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .Build();

        var caps = ImmutableArray.Create(
            TestFixtures.Classical_KEM(TestFixtures.ProviderA),
            TestFixtures.Classical_Sig(TestFixtures.ProviderA),
            TestFixtures.Aead(TestFixtures.ProviderA),
            TestFixtures.Kdf(TestFixtures.ProviderA),
            TestFixtures.Hash(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Equal(5, result.Count);
    }

    // ?? Null/default input guards ??

    [Fact]
    public void Select_NullPolicy_Throws()
    {
        var caps = ImmutableArray.Create(TestFixtures.Hash(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);
        Assert.Throws<ArgumentNullException>(() => _selector.Select(null!, caps, in ctx));
    }

    [Fact]
    public void Select_DefaultCapabilities_Throws()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .RequireCategory(AlgorithmCategory.Hash, 128)
            .Build();
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);
        Assert.Throws<ArgumentException>(() => _selector.Select(policy, default, in ctx));
    }

    // ?? Empty policy (no categories required) ? empty result ??

    [Fact]
    public void Select_NoCategoriesRequired_ReturnsEmpty()
    {
        var policy = TestFixtures.Policy()
            .WithMode(PolicySecurityMode.Classical)
            .Build();

        var caps = ImmutableArray.Create(TestFixtures.Hash(TestFixtures.ProviderA));
        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        var result = _selector.Select(policy, caps, in ctx);
        Assert.Empty(result);
    }
}
