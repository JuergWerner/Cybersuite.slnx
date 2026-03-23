using System.Collections.Immutable;
using Cybersuite.Abstractions;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// Shared test helpers and builders for creating well-formed test fixtures.
/// All helper methods produce valid, immutable objects consistent with the Architecture Canon.
/// </summary>
internal static class TestFixtures
{
    // ?? Provider IDs ??

    internal static readonly ProviderId ProviderA = new("ProviderA");
    internal static readonly ProviderId ProviderB = new("ProviderB");
    internal static readonly ProviderId ProviderBC = new("BouncyCastle");

    // ?? Algorithm IDs ??

    internal static readonly AlgorithmId MlKem768 = new("ML-KEM-768");
    internal static readonly AlgorithmId MlDsa65 = new("ML-DSA-65");
    internal static readonly AlgorithmId EcdhP384 = new("ECDH-P384-KEM");
    internal static readonly AlgorithmId EcdsaP384 = new("ECDSA-P384");
    internal static readonly AlgorithmId Aes256Gcm = new("AES-256-GCM");
    internal static readonly AlgorithmId HkdfSha384 = new("HKDF-SHA384");
    internal static readonly AlgorithmId Sha384 = new("SHA-384");

    // ?? Standard descriptors ??

    internal static AlgorithmDescriptor Classical_KEM(ProviderId provider, int strengthBits = 192) =>
        new(
            id: EcdhP384,
            provider: provider,
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false);

    internal static AlgorithmDescriptor Pqc_KEM(ProviderId provider, int strengthBits = 192) =>
        new(
            id: MlKem768,
            provider: provider,
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Pqc,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false,
            parameterSetId: new AlgorithmParameterSetId("ML-KEM-768"),
            operationalMaturity: AlgorithmOperationalMaturity.Experimental);

    internal static AlgorithmDescriptor Classical_Sig(ProviderId provider, int strengthBits = 192) =>
        new(
            id: EcdsaP384,
            provider: provider,
            category: AlgorithmCategory.Signature,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false);

    internal static AlgorithmDescriptor Pqc_Sig(ProviderId provider, int strengthBits = 192) =>
        new(
            id: MlDsa65,
            provider: provider,
            category: AlgorithmCategory.Signature,
            securityMode: AlgorithmSecurityMode.Pqc,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false,
            parameterSetId: new AlgorithmParameterSetId("ML-DSA-65"),
            operationalMaturity: AlgorithmOperationalMaturity.Experimental);

    internal static AlgorithmDescriptor Aead(ProviderId provider, int strengthBits = 256) =>
        new(
            id: Aes256Gcm,
            provider: provider,
            category: AlgorithmCategory.SymmetricAead,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false);

    internal static AlgorithmDescriptor Kdf(ProviderId provider, int strengthBits = 192) =>
        new(
            id: HkdfSha384,
            provider: provider,
            category: AlgorithmCategory.KeyDerivation,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false);

    internal static AlgorithmDescriptor Hash(ProviderId provider, int strengthBits = 192) =>
        new(
            id: Sha384,
            provider: provider,
            category: AlgorithmCategory.Hash,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(strengthBits),
            isFipsApproved: false);

    internal static AlgorithmDescriptor Hybrid_KEM(ProviderId provider) =>
        new(
            id: new AlgorithmId("X25519+ML-KEM-768"),
            provider: provider,
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Hybrid,
            strength: new SecurityStrength(128),
            isFipsApproved: false,
            hybridStrength: new HybridSecurityStrength(
                new SecurityStrength(128),
                new SecurityStrength(192)));

    internal static AlgorithmDescriptor Fips_KEM(ProviderId provider) =>
        new(
            id: EcdhP384,
            provider: provider,
            category: AlgorithmCategory.KeyEncapsulation,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(192),
            isFipsApproved: true);

    internal static AlgorithmDescriptor Deprecated_Hash(ProviderId provider) =>
        new(
            id: new AlgorithmId("SHA-1-DEPRECATED"),
            provider: provider,
            category: AlgorithmCategory.Hash,
            securityMode: AlgorithmSecurityMode.Classical,
            strength: new SecurityStrength(80),
            isFipsApproved: false,
            operationalMaturity: AlgorithmOperationalMaturity.Deprecated);

    // ?? Policy builder ??

    internal static TestPolicyBuilder Policy() => new();
}

/// <summary>
/// Fluent builder for creating test IPolicy instances without depending on PolicyLoader/JSON.
/// The PolicySnapshot constructor is internal, so we implement IPolicy directly.
/// </summary>
internal sealed class TestPolicyBuilder
{
    private PolicySecurityMode _mode = PolicySecurityMode.Classical;
    private bool _fipsRequired;
    private ImmutableDictionary<AlgorithmCategory, SecurityStrength>.Builder _minStrength = ImmutableDictionary.CreateBuilder<AlgorithmCategory, SecurityStrength>();
    private ImmutableArray<ProviderId>.Builder _allowlist = ImmutableArray.CreateBuilder<ProviderId>();
    private ImmutableDictionary<AlgorithmCategory, ProviderId>.Builder _pinnedByCategory = ImmutableDictionary.CreateBuilder<AlgorithmCategory, ProviderId>();
    private ImmutableDictionary<AlgorithmId, ProviderId>.Builder _pinnedByAlgorithm = ImmutableDictionary.CreateBuilder<AlgorithmId, ProviderId>();
    private string? _tenantId;

    public TestPolicyBuilder WithMode(PolicySecurityMode mode) { _mode = mode; return this; }
    public TestPolicyBuilder WithFips(bool fips = true) { _fipsRequired = fips; return this; }
    public TestPolicyBuilder WithTenant(string tenant) { _tenantId = tenant; return this; }

    public TestPolicyBuilder RequireCategory(AlgorithmCategory cat, int minBits)
    {
        _minStrength[cat] = new SecurityStrength(minBits);
        return this;
    }

    public TestPolicyBuilder AllowProvider(ProviderId provider) { _allowlist.Add(provider); return this; }

    public TestPolicyBuilder PinCategory(AlgorithmCategory cat, ProviderId provider) { _pinnedByCategory[cat] = provider; return this; }

    public TestPolicyBuilder PinAlgorithm(AlgorithmId alg, ProviderId provider) { _pinnedByAlgorithm[alg] = provider; return this; }

    public IPolicy Build() => new StubPolicy(
        _mode,
        _fipsRequired,
        _minStrength.ToImmutable(),
        _allowlist.ToImmutable(),
        _pinnedByCategory.ToImmutable(),
        _pinnedByAlgorithm.ToImmutable(),
        _tenantId);
}

/// <summary>
/// Minimal IPolicy implementation for unit tests, avoiding dependency on PolicyLoader/JSON pipeline.
/// </summary>
internal sealed class StubPolicy : IPolicy
{
    public string SchemaVersion => "1.0";
    public long Sequence => 1;
    public string? TenantId { get; }
    public PolicySecurityMode SecurityMode { get; }
    public bool FipsRequired { get; }
    public ImmutableDictionary<AlgorithmCategory, SecurityStrength> MinimumStrengthByCategory { get; }
    public ImmutableArray<ProviderId> ProviderAllowlist { get; }
    public ImmutableDictionary<AlgorithmCategory, ProviderId> PinnedProviderByCategory { get; }
    public ImmutableDictionary<AlgorithmId, ProviderId> PinnedProviderByAlgorithm { get; }
    public ReadOnlyMemory<byte> PolicyHash { get; }

    public StubPolicy(
        PolicySecurityMode mode,
        bool fipsRequired,
        ImmutableDictionary<AlgorithmCategory, SecurityStrength> minStrength,
        ImmutableArray<ProviderId> allowlist,
        ImmutableDictionary<AlgorithmCategory, ProviderId> pinnedByCategory,
        ImmutableDictionary<AlgorithmId, ProviderId> pinnedByAlgorithm,
        string? tenantId)
    {
        SecurityMode = mode;
        FipsRequired = fipsRequired;
        MinimumStrengthByCategory = minStrength;
        ProviderAllowlist = allowlist;
        PinnedProviderByCategory = pinnedByCategory;
        PinnedProviderByAlgorithm = pinnedByAlgorithm;
        TenantId = tenantId;
        PolicyHash = new byte[48]; // zeroed stub hash
    }
}
