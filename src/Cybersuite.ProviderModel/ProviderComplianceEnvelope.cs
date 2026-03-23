using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderModel;

/// <summary>
/// Canonical provider-side compliance declaration transported by manifest and handshake.
/// This envelope carries boundary truth, validation claims, and a deterministic SHA-384 hash
/// so the host can compare manifest and runtime declarations fail-closed.
/// </summary>
public sealed record ProviderComplianceEnvelope
{
    /// <summary>Provider's operational security classification (ReferenceInProcess / ProductionIsolated / ValidatedBoundary).</summary>
    public ProviderSecurityClass SecurityClass { get; }

    /// <summary>Minimum boundary class derived from the security class and isolation mode.</summary>
    public RequiredBoundaryClass BoundaryClass { get; }

    /// <summary>Whether the provider declares operation inside a validated cryptographic boundary (e.g. FIPS 140-3 module).</summary>
    public bool DeclaredValidatedBoundary { get; }

    /// <summary>Optional declared cryptographic module name (e.g. "BouncyCastle FIPS Java Module"). For audit only.</summary>
    public string? DeclaredModuleName { get; }

    /// <summary>Optional declared certificate or listing reference (e.g. CMVP certificate number). For audit only.</summary>
    public string? DeclaredCertificateReference { get; }

    /// <summary>Optional declared module version string. For audit only.</summary>
    public string? DeclaredModuleVersion { get; }

    /// <summary>Whether the provider supports non-exportable (hardware-bound) key storage.</summary>
    public bool SupportsNonExportableKeys { get; }

    /// <summary>Whether the provider supports raw secret egress (exporting secret key bytes). True for software providers.</summary>
    public bool SupportsRawSecretEgress { get; }

    /// <summary>Provider-declared attestation mode (None / Optional / Required).</summary>
    public AttestationMode AttestationMode { get; }

    /// <summary>Deterministic SHA-384 hash of the canonical envelope representation, used for manifest-vs-handshake comparison.</summary>
    public ImmutableArray<byte> EnvelopeHashSha384 { get; }

    public ProviderComplianceEnvelope(
        ProviderSecurityClass securityClass,
        RequiredBoundaryClass boundaryClass,
        bool declaredValidatedBoundary,
        string? declaredModuleName,
        string? declaredCertificateReference,
        string? declaredModuleVersion,
        bool supportsNonExportableKeys,
        bool supportsRawSecretEgress,
        AttestationMode attestationMode)
    {
        if (declaredValidatedBoundary && boundaryClass != RequiredBoundaryClass.ValidatedBoundary)
            boundaryClass = RequiredBoundaryClass.ValidatedBoundary;

        if (boundaryClass == RequiredBoundaryClass.ValidatedBoundary)
            declaredValidatedBoundary = true;

        SecurityClass = securityClass;
        BoundaryClass = boundaryClass;
        DeclaredValidatedBoundary = declaredValidatedBoundary;
        DeclaredModuleName = NormalizeOrNull(declaredModuleName);
        DeclaredCertificateReference = NormalizeOrNull(declaredCertificateReference);
        DeclaredModuleVersion = NormalizeOrNull(declaredModuleVersion);
        SupportsNonExportableKeys = supportsNonExportableKeys;
        SupportsRawSecretEgress = supportsRawSecretEgress;
        AttestationMode = attestationMode;
        EnvelopeHashSha384 = ImmutableArray.CreateRange(ComputeEnvelopeHash());
    }

    public static ProviderComplianceEnvelope ReferenceInProcessDefault { get; } =
        new(
            securityClass: ProviderSecurityClass.ReferenceInProcess,
            boundaryClass: RequiredBoundaryClass.None,
            declaredValidatedBoundary: false,
            declaredModuleName: null,
            declaredCertificateReference: null,
            declaredModuleVersion: null,
            supportsNonExportableKeys: false,
            supportsRawSecretEgress: true,
            attestationMode: AttestationMode.None);

    public static ProviderComplianceEnvelope FromLegacyProfile(
        ProviderIsolationMode isolationMode,
        ProviderComplianceProfile? complianceProfile)
    {
        ProviderComplianceProfile profile = complianceProfile ?? ProviderComplianceProfile.None;

        RequiredBoundaryClass boundaryClass = profile.DeclaredValidatedBoundary
            ? RequiredBoundaryClass.ValidatedBoundary
            : isolationMode switch
            {
                ProviderIsolationMode.InProcess => RequiredBoundaryClass.None,
                ProviderIsolationMode.OutOfProcess => RequiredBoundaryClass.IsolatedProcess,
                ProviderIsolationMode.HardwareBoundary => RequiredBoundaryClass.IsolatedProcess,
                _ => RequiredBoundaryClass.None
            };

        ProviderSecurityClass securityClass = profile.DeclaredValidatedBoundary
            ? ProviderSecurityClass.ValidatedBoundary
            : isolationMode == ProviderIsolationMode.InProcess
                ? ProviderSecurityClass.ReferenceInProcess
                : ProviderSecurityClass.ProductionIsolated;

        return new ProviderComplianceEnvelope(
            securityClass,
            boundaryClass,
            profile.DeclaredValidatedBoundary,
            profile.DeclaredModuleName,
            profile.DeclaredCertificateReference,
            declaredModuleVersion: null,
            supportsNonExportableKeys: profile.DeclaredValidatedBoundary,
            supportsRawSecretEgress: true,
            attestationMode: AttestationMode.None);
    }

    public static ProviderComplianceEnvelope FromLegacyHandshake(bool fipsBoundaryDeclared)
        => fipsBoundaryDeclared
            ? new ProviderComplianceEnvelope(
                securityClass: ProviderSecurityClass.ValidatedBoundary,
                boundaryClass: RequiredBoundaryClass.ValidatedBoundary,
                declaredValidatedBoundary: true,
                declaredModuleName: null,
                declaredCertificateReference: null,
                declaredModuleVersion: null,
                supportsNonExportableKeys: false,
                supportsRawSecretEgress: true,
                attestationMode: AttestationMode.None)
            : ReferenceInProcessDefault;

    public ProviderComplianceProfile ToComplianceProfile()
        => ProviderComplianceProfile.FromEnvelope(this);

    public bool SemanticallyEquals(ProviderComplianceEnvelope? other)
    {
        if (other is null)
            return false;

        return SecurityClass == other.SecurityClass
            && BoundaryClass == other.BoundaryClass
            && DeclaredValidatedBoundary == other.DeclaredValidatedBoundary
            && string.Equals(DeclaredModuleName, other.DeclaredModuleName, StringComparison.Ordinal)
            && string.Equals(DeclaredCertificateReference, other.DeclaredCertificateReference, StringComparison.Ordinal)
            && string.Equals(DeclaredModuleVersion, other.DeclaredModuleVersion, StringComparison.Ordinal)
            && SupportsNonExportableKeys == other.SupportsNonExportableKeys
            && SupportsRawSecretEgress == other.SupportsRawSecretEgress
            && AttestationMode == other.AttestationMode
            && FixedTimeHashEquals(other.EnvelopeHashSha384);
    }

    private byte[] ComputeEnvelopeHash()
    {
        string canonical = GetCanonicalString();
        byte[] canonicalBytes = Encoding.UTF8.GetBytes(canonical);
        byte[] hash = SHA384.HashData(canonicalBytes);
        return hash;
    }

    private string GetCanonicalString()
    {
        return string.Join(
            '|',
            "ProviderComplianceEnvelopeV1",
            ((int)SecurityClass).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ((int)BoundaryClass).ToString(System.Globalization.CultureInfo.InvariantCulture),
            DeclaredValidatedBoundary ? "1" : "0",
            DeclaredModuleName ?? string.Empty,
            DeclaredCertificateReference ?? string.Empty,
            DeclaredModuleVersion ?? string.Empty,
            SupportsNonExportableKeys ? "1" : "0",
            SupportsRawSecretEgress ? "1" : "0",
            ((int)AttestationMode).ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private bool FixedTimeHashEquals(ImmutableArray<byte> other)
    {
        if (EnvelopeHashSha384.IsDefaultOrEmpty || other.IsDefaultOrEmpty || EnvelopeHashSha384.Length != other.Length)
            return false;

        byte[] left = EnvelopeHashSha384.ToArray();
        byte[] right = other.ToArray();
        bool equal = CryptographicOperations.FixedTimeEquals(left, right);
        CryptographicOperations.ZeroMemory(left);
        CryptographicOperations.ZeroMemory(right);
        return equal;
    }

    private static string? NormalizeOrNull(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Normalize(NormalizationForm.FormC);
}
