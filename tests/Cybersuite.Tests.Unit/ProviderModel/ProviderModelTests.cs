using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;
using Xunit;

namespace Cybersuite.Tests.Unit.ProviderModel;

/// <summary>
/// Tests for ProviderIdentity constructor guards and normalization per [PM-000].
/// </summary>
public sealed class ProviderIdentityTests
{
    [Fact]
    public void Constructor_EmptyProviderId_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ProviderIdentity(
            new ProviderId(""), "1.0", "abc123", null));
    }

    [Fact]
    public void Constructor_EmptyVersion_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ProviderIdentity(
            new ProviderId("P"), "", "abc123", null));
    }

    [Fact]
    public void Constructor_EmptyBuildHash_Throws()
    {
        Assert.Throws<ArgumentException>(() => new ProviderIdentity(
            new ProviderId("P"), "1.0", "", null));
    }

    [Fact]
    public void Constructor_Valid_PropertiesSet()
    {
        var id = new ProviderIdentity(new ProviderId("BC"), "2.6.2", "AABB", "FP");
        Assert.Equal("BC", id.ProviderId.Value);
        Assert.Equal("2.6.2", id.Version);
        Assert.Equal("AABB", id.BuildHash);
        Assert.Equal("FP", id.SignatureFingerprint);
    }

    [Fact]
    public void Constructor_NullFingerprint_IsNull()
    {
        var id = new ProviderIdentity(new ProviderId("BC"), "1.0", "H", null);
        Assert.Null(id.SignatureFingerprint);
    }
}

/// <summary>
/// Tests for CapabilitySnapshot: deterministic hash, canonical bytes, and immutability per [PM-010].
/// </summary>
public sealed class CapabilitySnapshotTests
{
    private static ProviderIdentity MakeIdentity() =>
        new(new ProviderId("Test"), "1.0", "BUILD_HASH", null);

    [Fact]
    public void Create_EmptyAlgorithms_Succeeds()
    {
        var snapshot = CapabilitySnapshot.Create(MakeIdentity(), ImmutableArray<AlgorithmDescriptor>.Empty);
        Assert.Empty(snapshot.Algorithms);
        Assert.Equal(48, snapshot.CapabilityHashSha384.Length);
    }

    [Fact]
    public void Create_DeterministicHash_SameInput_SameHash()
    {
        var identity = MakeIdentity();
        var algs = ImmutableArray.Create(TestFixtures.Hash(new ProviderId("Test")));

        var snap1 = CapabilitySnapshot.Create(identity, algs);
        var snap2 = CapabilitySnapshot.Create(identity, algs);

        Assert.True(snap1.CapabilityHashSha384.Span.SequenceEqual(snap2.CapabilityHashSha384.Span));
    }

    [Fact]
    public void Create_DifferentAlgorithms_DifferentHash()
    {
        var identity = MakeIdentity();
        var provider = new ProviderId("Test");

        var snap1 = CapabilitySnapshot.Create(identity, ImmutableArray.Create(TestFixtures.Hash(provider)));
        var snap2 = CapabilitySnapshot.Create(identity, ImmutableArray.Create(TestFixtures.Aead(provider)));

        Assert.False(snap1.CapabilityHashSha384.Span.SequenceEqual(snap2.CapabilityHashSha384.Span));
    }

    [Fact]
    public void GetCanonicalBytes_Deterministic()
    {
        var identity = MakeIdentity();
        var algs = ImmutableArray.Create(TestFixtures.Hash(new ProviderId("Test")));
        var snap = CapabilitySnapshot.Create(identity, algs);

        byte[] bytes1 = snap.GetCanonicalBytes();
        byte[] bytes2 = snap.GetCanonicalBytes();
        Assert.True(bytes1.AsSpan().SequenceEqual(bytes2));
        Assert.True(bytes1.Length > 0);
    }

    [Fact]
    public void Create_NullIdentity_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            CapabilitySnapshot.Create(null!, ImmutableArray<AlgorithmDescriptor>.Empty));
    }

    [Fact]
    public void Create_WithArtifactProfiles_Preserved()
    {
        var identity = MakeIdentity();
        var algs = ImmutableArray.Create(TestFixtures.Aead(new ProviderId("Test")));
        var profiles = ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile>.Empty
            .Add(new AlgorithmId("AES-256-GCM"), new CapabilityArtifactProfile(
                symmetricKeyBytes: 32, nonceBytes: 12, tagBytes: 16));

        var snap = CapabilitySnapshot.Create(identity, algs, profiles);
        Assert.True(snap.ArtifactProfilesByAlgorithmId.ContainsKey(new AlgorithmId("AES-256-GCM")));
        Assert.Equal(32, snap.ArtifactProfilesByAlgorithmId[new AlgorithmId("AES-256-GCM")].SymmetricKeyBytes);
    }
}

/// <summary>
/// Tests for CapabilityArtifactProfile per [PM-010].
/// </summary>
public sealed class CapabilityArtifactProfileTests
{
    [Fact]
    public void Empty_AllZeros()
    {
        var e = CapabilityArtifactProfile.Empty;
        Assert.Equal(0, e.PublicKeyBytes);
        Assert.Equal(0, e.CiphertextBytes);
        Assert.Equal(0, e.TagBytes);
    }

    [Fact]
    public void Constructor_NegativeValues_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityArtifactProfile(publicKeyBytes: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityArtifactProfile(ciphertextBytes: -1));
        Assert.Throws<ArgumentOutOfRangeException>(() => new CapabilityArtifactProfile(signatureBytes: -1));
    }

    [Fact]
    public void Constructor_ValidSizes_RoundTrips()
    {
        var p = new CapabilityArtifactProfile(
            publicKeyBytes: 1184, ciphertextBytes: 1088, sharedSecretBytes: 32);
        Assert.Equal(1184, p.PublicKeyBytes);
        Assert.Equal(1088, p.CiphertextBytes);
        Assert.Equal(32, p.SharedSecretBytes);
    }
}

/// <summary>
/// Tests for ProviderComplianceProfile per [CMP-000].
/// </summary>
public sealed class ProviderComplianceProfileTests
{
    [Fact]
    public void None_DefaultsToNotValidated()
    {
        var none = ProviderComplianceProfile.None;
        Assert.False(none.DeclaredValidatedBoundary);
        Assert.Null(none.DeclaredModuleName);
        Assert.Null(none.DeclaredCertificateReference);
    }

    [Fact]
    public void Constructor_ValidatedBoundary_Preserved()
    {
        var p = new ProviderComplianceProfile(true, "FIPS-Module-1", "CERT-REF-123");
        Assert.True(p.DeclaredValidatedBoundary);
        Assert.Equal("FIPS-Module-1", p.DeclaredModuleName);
        Assert.Equal("CERT-REF-123", p.DeclaredCertificateReference);
    }

    [Fact]
    public void Constructor_WhitespaceModuleName_NormalizedToNull()
    {
        var p = new ProviderComplianceProfile(false, "  ", null);
        Assert.Null(p.DeclaredModuleName);
    }
}

/// <summary>
/// Tests for ProviderMetadata including ComplianceProfile integration.
/// </summary>
public sealed class ProviderMetadataTests
{
    [Fact]
    public void Constructor_NullComplianceProfile_DefaultsToNone()
    {
        var identity = new ProviderIdentity(new ProviderId("P"), "1.0", "H", null);
        var meta = new ProviderMetadata(identity, "Vendor", ProviderIsolationMode.InProcess,
            ProviderTrustState.Trusted, false);

        Assert.False(meta.ComplianceProfile.DeclaredValidatedBoundary);
    }

    [Fact]
    public void Constructor_WithComplianceProfile_Preserved()
    {
        var identity = new ProviderIdentity(new ProviderId("P"), "1.0", "H", null);
        var compliance = new ProviderComplianceProfile(true, "Module", "Cert");
        var meta = new ProviderMetadata(identity, "Vendor", ProviderIsolationMode.InProcess,
            ProviderTrustState.Trusted, false, compliance);

        Assert.True(meta.ComplianceProfile.DeclaredValidatedBoundary);
    }
}


/// <summary>
/// Tests for ProviderComplianceEnvelope as the Wave 1 canonical provider boundary declaration.
/// </summary>
public sealed class ProviderComplianceEnvelopeTests
{
    [Fact]
    public void ReferenceInProcessDefault_HasExpectedShape()
    {
        var envelope = ProviderComplianceEnvelope.ReferenceInProcessDefault;
        Assert.Equal(ProviderSecurityClass.ReferenceInProcess, envelope.SecurityClass);
        Assert.Equal(RequiredBoundaryClass.None, envelope.BoundaryClass);
        Assert.False(envelope.DeclaredValidatedBoundary);
        Assert.Equal(48, envelope.EnvelopeHashSha384.Length);
    }

    [Fact]
    public void Constructor_ValidatedBoundary_PromotesBoundaryClass()
    {
        var envelope = new ProviderComplianceEnvelope(
            securityClass: ProviderSecurityClass.ValidatedBoundary,
            boundaryClass: RequiredBoundaryClass.None,
            declaredValidatedBoundary: true,
            declaredModuleName: "Module",
            declaredCertificateReference: "Cert",
            declaredModuleVersion: "1.0.0",
            supportsNonExportableKeys: true,
            supportsRawSecretEgress: false,
            attestationMode: AttestationMode.Optional);

        Assert.Equal(RequiredBoundaryClass.ValidatedBoundary, envelope.BoundaryClass);
        Assert.True(envelope.DeclaredValidatedBoundary);
    }

    [Fact]
    public void FromLegacyHandshake_NoFipsBoundary_DefaultsToReferenceInProcess()
    {
        var envelope = ProviderComplianceEnvelope.FromLegacyHandshake(fipsBoundaryDeclared: false);

        Assert.Equal(ProviderSecurityClass.ReferenceInProcess, envelope.SecurityClass);
        Assert.Equal(RequiredBoundaryClass.None, envelope.BoundaryClass);
        Assert.False(envelope.DeclaredValidatedBoundary);
    }

    [Fact]
    public void SemanticallyEquals_SameFields_True()
    {
        var left = new ProviderComplianceEnvelope(
            ProviderSecurityClass.ProductionIsolated,
            RequiredBoundaryClass.IsolatedProcess,
            false,
            "Module",
            "Cert",
            "1.0.0",
            false,
            true,
            AttestationMode.None);
        var right = new ProviderComplianceEnvelope(
            ProviderSecurityClass.ProductionIsolated,
            RequiredBoundaryClass.IsolatedProcess,
            false,
            "Module",
            "Cert",
            "1.0.0",
            false,
            true,
            AttestationMode.None);

        Assert.True(left.SemanticallyEquals(right));
    }
}
