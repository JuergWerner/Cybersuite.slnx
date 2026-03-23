using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.Selection;
using Xunit;

namespace Cybersuite.Test.Property;

/// <summary>
/// Property-based / invariant tests for the AlgorithmSelector per [SEL-000].
/// These tests verify architectural invariants that must hold for ALL valid inputs:
///
/// Invariant 1 — DETERMINISM: Same input always produces the same output,
///               regardless of capability array ordering.
/// Invariant 2 — ANTI-DOWNGRADE: PQC policy never selects Classical asymmetric algorithms;
///               Classical policy never selects PQC asymmetric algorithms.
/// Invariant 3 — STRENGTH FLOOR: No selected algorithm has strength below the policy minimum.
/// Invariant 4 — FAIL-CLOSED: If no candidate exists for a required category, selection throws.
/// Invariant 5 — FIPS ENFORCEMENT: When FIPS required, all selected algorithms are FIPS-approved.
/// </summary>
public sealed class SelectionInvariantTests
{
    private readonly AlgorithmSelector _selector = new();

    // ?? Invariant 1: Determinism across capability orderings ??

    [Fact]
    public void Invariant_Deterministic_OrderIndependent()
    {
        var provA = new ProviderId("Alpha");
        var provZ = new ProviderId("Zulu");

        var d1 = new AlgorithmDescriptor(
            new AlgorithmId("AES-128-GCM"), provA, AlgorithmCategory.SymmetricAead,
            AlgorithmSecurityMode.Classical, new SecurityStrength(128), false);
        var d2 = new AlgorithmDescriptor(
            new AlgorithmId("AES-256-GCM"), provZ, AlgorithmCategory.SymmetricAead,
            AlgorithmSecurityMode.Classical, new SecurityStrength(256), false);

        var policy = new StubPolicy(
            PolicySecurityMode.Classical, false,
            ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Empty
                .Add(AlgorithmCategory.SymmetricAead, new SecurityStrength(128)),
            ImmutableArray<ProviderId>.Empty,
            ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty,
            ImmutableDictionary<AlgorithmId, ProviderId>.Empty);

        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        // Order A: d1 first
        var resultA = _selector.Select(policy, ImmutableArray.Create(d1, d2), in ctx);
        // Order B: d2 first
        var resultB = _selector.Select(policy, ImmutableArray.Create(d2, d1), in ctx);

        // Both must produce the exact same winner
        Assert.Equal(resultA[AlgorithmCategory.SymmetricAead].Id, resultB[AlgorithmCategory.SymmetricAead].Id);
        Assert.Equal(resultA[AlgorithmCategory.SymmetricAead].Provider, resultB[AlgorithmCategory.SymmetricAead].Provider);
    }

    // ?? Invariant 2: Anti-downgrade (PQC policy blocks Classical for asymmetric) ??

    [Fact]
    public void Invariant_AntiDowngrade_PqcPolicyNeverSelectsClassicalKEM()
    {
        var provider = new ProviderId("P");

        var classicalKem = new AlgorithmDescriptor(
            new AlgorithmId("ECDH-P384"), provider, AlgorithmCategory.KeyEncapsulation,
            AlgorithmSecurityMode.Classical, new SecurityStrength(256), false);
        var pqcKem = new AlgorithmDescriptor(
            new AlgorithmId("ML-KEM-768"), provider, AlgorithmCategory.KeyEncapsulation,
            AlgorithmSecurityMode.Pqc, new SecurityStrength(192), false);

        var policy = new StubPolicy(
            PolicySecurityMode.Pqc, false,
            ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Empty
                .Add(AlgorithmCategory.KeyEncapsulation, new SecurityStrength(128)),
            ImmutableArray<ProviderId>.Empty,
            ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty,
            ImmutableDictionary<AlgorithmId, ProviderId>.Empty);

        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);
        var result = _selector.Select(policy, ImmutableArray.Create(classicalKem, pqcKem), in ctx);

        // Must pick PQC, never Classical, even though Classical has higher strength
        Assert.Equal(AlgorithmSecurityMode.Pqc, result[AlgorithmCategory.KeyEncapsulation].SecurityMode);
    }

    // ?? Invariant 3: Strength floor ??

    [Fact]
    public void Invariant_StrengthFloor_SelectedMeetsMinimum()
    {
        var provider = new ProviderId("P");

        var descriptors = ImmutableArray.Create(
            new AlgorithmDescriptor(new AlgorithmId("SHA-256"), provider, AlgorithmCategory.Hash,
                AlgorithmSecurityMode.Classical, new SecurityStrength(128), false),
            new AlgorithmDescriptor(new AlgorithmId("SHA-384"), provider, AlgorithmCategory.Hash,
                AlgorithmSecurityMode.Classical, new SecurityStrength(192), false),
            new AlgorithmDescriptor(new AlgorithmId("SHA-512"), provider, AlgorithmCategory.Hash,
                AlgorithmSecurityMode.Classical, new SecurityStrength(256), false));

        var minBits = 192;
        var policy = new StubPolicy(
            PolicySecurityMode.Classical, false,
            ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Empty
                .Add(AlgorithmCategory.Hash, new SecurityStrength(minBits)),
            ImmutableArray<ProviderId>.Empty,
            ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty,
            ImmutableDictionary<AlgorithmId, ProviderId>.Empty);

        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);
        var result = _selector.Select(policy, descriptors, in ctx);

        Assert.True(result[AlgorithmCategory.Hash].Strength.Bits >= minBits);
    }

    // ?? Invariant 4: Fail-closed ??

    [Fact]
    public void Invariant_FailClosed_NoCandidateThrows()
    {
        var policy = new StubPolicy(
            PolicySecurityMode.Pqc, false,
            ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Empty
                .Add(AlgorithmCategory.Signature, new SecurityStrength(128)),
            ImmutableArray<ProviderId>.Empty,
            ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty,
            ImmutableDictionary<AlgorithmId, ProviderId>.Empty);

        var ctx = new SelectionContext(null, ExecutionProfile.Dev, null);

        // Empty capabilities ? must throw
        var ex = Assert.Throws<SelectionFailedException>(() =>
            _selector.Select(policy, ImmutableArray<AlgorithmDescriptor>.Empty, in ctx));
        Assert.Equal(AlgorithmCategory.Signature, ex.Category);
    }

    // ?? Invariant 5: FIPS enforcement ??

    [Fact]
    public void Invariant_Fips_AllSelectedAreFipsApproved()
    {
        var provider = new ProviderId("P");

        var nonFips = new AlgorithmDescriptor(
            new AlgorithmId("AES-128-GCM"), provider, AlgorithmCategory.SymmetricAead,
            AlgorithmSecurityMode.Classical, new SecurityStrength(128), false);
        var fips = new AlgorithmDescriptor(
            new AlgorithmId("AES-256-GCM"), provider, AlgorithmCategory.SymmetricAead,
            AlgorithmSecurityMode.Classical, new SecurityStrength(256), true);

        var policy = new StubPolicy(
            PolicySecurityMode.Classical, true,
            ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Empty
                .Add(AlgorithmCategory.SymmetricAead, new SecurityStrength(128)),
            ImmutableArray<ProviderId>.Empty,
            ImmutableDictionary<AlgorithmCategory, ProviderId>.Empty,
            ImmutableDictionary<AlgorithmId, ProviderId>.Empty);

        var ctx = new SelectionContext(null, ExecutionProfile.Prod, null);
        var result = _selector.Select(policy, ImmutableArray.Create(nonFips, fips), in ctx);

        Assert.True(result[AlgorithmCategory.SymmetricAead].IsFipsApproved);
    }

    // ?? Invariant: Capability hash determinism ??

    [Fact]
    public void Invariant_CapabilitySnapshot_HashDeterministic()
    {
        var identity = new ProviderModel.ProviderIdentity(new ProviderId("T"), "1.0", "H", null);
        var algs = ImmutableArray.Create(
            new AlgorithmDescriptor(new AlgorithmId("A"), new ProviderId("T"), AlgorithmCategory.Hash,
                AlgorithmSecurityMode.Classical, new SecurityStrength(192), false),
            new AlgorithmDescriptor(new AlgorithmId("B"), new ProviderId("T"), AlgorithmCategory.Hash,
                AlgorithmSecurityMode.Classical, new SecurityStrength(128), false));

        // Input in A,B order
        var snap1 = ProviderModel.CapabilitySnapshot.Create(identity, algs);

        // Input in B,A order
        var reversed = ImmutableArray.Create(algs[1], algs[0]);
        var snap2 = ProviderModel.CapabilitySnapshot.Create(identity, reversed);

        // Hash must be identical regardless of input order
        Assert.True(snap1.CapabilityHashSha384.Span.SequenceEqual(snap2.CapabilityHashSha384.Span));
    }
}

/// <summary>
/// Minimal IPolicy implementation for property tests.
/// </summary>
internal sealed class StubPolicy : IPolicy
{
    public string SchemaVersion => "1.0";
    public long Sequence => 1;
    public string? TenantId => null;
    public PolicySecurityMode SecurityMode { get; }
    public bool FipsRequired { get; }
    public ImmutableDictionary<AlgorithmCategory, SecurityStrength> MinimumStrengthByCategory { get; }
    public ImmutableArray<ProviderId> ProviderAllowlist { get; }
    public ImmutableDictionary<AlgorithmCategory, ProviderId> PinnedProviderByCategory { get; }
    public ImmutableDictionary<AlgorithmId, ProviderId> PinnedProviderByAlgorithm { get; }
    public ReadOnlyMemory<byte> PolicyHash { get; } = new byte[48];

    public StubPolicy(
        PolicySecurityMode mode, bool fips,
        ImmutableDictionary<AlgorithmCategory, SecurityStrength> min,
        ImmutableArray<ProviderId> allow,
        ImmutableDictionary<AlgorithmCategory, ProviderId> pinCat,
        ImmutableDictionary<AlgorithmId, ProviderId> pinAlg)
    {
        SecurityMode = mode;
        FipsRequired = fips;
        MinimumStrengthByCategory = min;
        ProviderAllowlist = allow;
        PinnedProviderByCategory = pinCat;
        PinnedProviderByAlgorithm = pinAlg;
    }
}
