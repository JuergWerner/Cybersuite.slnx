namespace Cybersuite.Abstractions;

/// <summary>
/// Immutable descriptor for a single algorithm capability advertised by a provider.
/// This is the fundamental unit of the Cybersuite capability model [ARC-200].
///
/// Each descriptor binds an <see cref="AlgorithmId"/> to the <see cref="ProviderId"/> that
/// implements it, along with classification metadata required by the selection engine,
/// compliance gates, and policy enforcement:
/// <list type="bullet">
///   <item><see cref="Category"/> — canonical algorithm family (KEM, Signature, AEAD, KDF, …).</item>
///   <item><see cref="SecurityMode"/> — Classical / PQC / Hybrid classification for anti-downgrade checks.</item>
///   <item><see cref="Strength"/> — effective security strength in bits for minimum-strength filtering.</item>
///   <item><see cref="IsFipsApproved"/> — provider-declared FIPS flag consumed by compliance gates.</item>
///   <item><see cref="OperationalMaturity"/> — Stable / Experimental / Deprecated lifecycle tag.</item>
///   <item><see cref="EncodingProfile"/> — default import/export encoding for interoperability.</item>
/// </list>
///
/// Descriptors are collected into immutable <see cref="ImmutableArray{AlgorithmDescriptor}"/>
/// capability snapshots during provider handshake and remain frozen for the session lifetime.
/// The selection engine (<see cref="ISelectionEngine"/>) consumes these snapshots to resolve
/// the winning algorithm per required category.
///
/// Validation: the constructor rejects invalid combinations (empty IDs, missing hybrid strength,
/// hybrid strength on non-hybrid algorithms) fail-closed.
/// </summary>
public sealed class AlgorithmDescriptor
{
    public AlgorithmId Id { get; }
    public ProviderId Provider { get; }
    public AlgorithmCategory Category { get; }

    /// <summary>
    /// Algorithm mode classification (Classical / PQC / Hybrid). Relevant for asymmetric categories.
    /// </summary>
    public AlgorithmSecurityMode SecurityMode { get; }

    /// <summary>
    /// Effective strength used for ordering/selection. For hybrid algorithms this is typically min(classical, pqc).
    /// </summary>
    public SecurityStrength Strength { get; }

    /// <summary>
    /// Optional additional hybrid strength detail (for audit/debug). Effective ordering uses <see cref="Strength"/>.
    /// Must be present iff <see cref="SecurityMode"/> == Hybrid.
    /// </summary>
    public HybridSecurityStrength? HybridStrength { get; }

    /// <summary>
    /// Provider-declared flag used by Compliance filtering. Real FIPS compliance depends on provider boundary/certificate.
    /// </summary>
    public bool IsFipsApproved { get; }

    /// <summary>
    /// Optional concrete parameter-set identifier (e.g., ML-KEM-768, ML-DSA-65).
    /// Additive field; current classical bindings may leave it null.
    /// </summary>
    public AlgorithmParameterSetId? ParameterSetId { get; }

    /// <summary>
    /// Operational maturity of the capability (Stable / Experimental / Deprecated).
    /// This allows provider-scoped catalogs to mix stable classical and experimental PQC offerings.
    /// </summary>
    public AlgorithmOperationalMaturity OperationalMaturity { get; }

    /// <summary>
    /// Default encoding profile for import/export/interoperability. This is metadata only.
    /// Providers may still support multiple explicit export/import profiles later.
    /// </summary>
    public AlgorithmEncodingProfile EncodingProfile { get; }

    /// <summary>
    /// Creates a new algorithm descriptor with full validation.
    /// </summary>
    /// <param name="id">Unique algorithm identifier (e.g. "ML-KEM-768", "AES-256-GCM"). Must be non-empty.</param>
    /// <param name="provider">Provider that implements this algorithm. Must be non-empty.</param>
    /// <param name="category">Canonical algorithm family classification.</param>
    /// <param name="securityMode">Classical / PQC / Hybrid classification for anti-downgrade enforcement.</param>
    /// <param name="strength">Effective security strength in bits used for minimum-strength policy filtering.</param>
    /// <param name="isFipsApproved">Provider-declared FIPS approval status. Actual compliance depends on boundary certification.</param>
    /// <param name="hybridStrength">Decomposed classical + PQC strength detail. Required iff <paramref name="securityMode"/> is <see cref="AlgorithmSecurityMode.Hybrid"/>.</param>
    /// <param name="parameterSetId">Optional NIST parameter set identifier (e.g. ML-KEM-768). Must be non-empty when provided.</param>
    /// <param name="operationalMaturity">Lifecycle maturity tag (Stable / Experimental / Deprecated). Defaults to Stable.</param>
    /// <param name="encodingProfile">Default encoding for key import/export. Defaults to ProviderNative.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when: <paramref name="id"/> or <paramref name="provider"/> is empty,
    /// <paramref name="hybridStrength"/> is missing for Hybrid mode or present for non-Hybrid mode,
    /// or <paramref name="parameterSetId"/> is provided with an empty value.
    /// </exception>
    public AlgorithmDescriptor(
        AlgorithmId id,
        ProviderId provider,
        AlgorithmCategory category,
        AlgorithmSecurityMode securityMode,
        SecurityStrength strength,
        bool isFipsApproved,
        HybridSecurityStrength? hybridStrength = null,
        AlgorithmParameterSetId? parameterSetId = null,
        AlgorithmOperationalMaturity operationalMaturity = AlgorithmOperationalMaturity.Stable,
        AlgorithmEncodingProfile encodingProfile = AlgorithmEncodingProfile.ProviderNative)
    {
        if (string.IsNullOrWhiteSpace(id.Value))
            throw new ArgumentException("AlgorithmId.Value must be non-empty.", nameof(id));

        if (string.IsNullOrWhiteSpace(provider.Value))
            throw new ArgumentException("ProviderId.Value must be non-empty.", nameof(provider));

        if (securityMode == AlgorithmSecurityMode.Hybrid && hybridStrength is null)
            throw new ArgumentException("HybridStrength is required when SecurityMode is Hybrid.", nameof(hybridStrength));

        if (securityMode != AlgorithmSecurityMode.Hybrid && hybridStrength is not null)
            throw new ArgumentException("HybridStrength must be null unless SecurityMode is Hybrid.", nameof(hybridStrength));

        if (parameterSetId is AlgorithmParameterSetId ps && string.IsNullOrWhiteSpace(ps.Value))
            throw new ArgumentException("ParameterSetId.Value must be non-empty when provided.", nameof(parameterSetId));

        Id = id;
        Provider = provider;
        Category = category;
        SecurityMode = securityMode;
        Strength = strength;
        IsFipsApproved = isFipsApproved;
        HybridStrength = hybridStrength;
        ParameterSetId = parameterSetId;
        OperationalMaturity = operationalMaturity;
        EncodingProfile = encodingProfile;
    }
}