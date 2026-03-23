namespace Cybersuite.ProviderModel;

/// <summary>
/// Provider-level compliance metadata. This is distinct from algorithm-level approval flags.
/// It models the second half of the dual compliance gate and is now derived from the canonical
/// <see cref="ProviderComplianceEnvelope"/> whenever an envelope is available.
/// </summary>
public sealed class ProviderComplianceProfile
{
    /// <summary>
    /// Provider declares that it is operating inside a validated or otherwise approved boundary.
    /// This is metadata and does not by itself prove certification.
    /// </summary>
    public bool DeclaredValidatedBoundary { get; }

    /// <summary>
    /// Optional module or package name used for audit / approval mapping.
    /// </summary>
    public string? DeclaredModuleName { get; }

    /// <summary>
    /// Optional certificate / listing / profile reference.
    /// </summary>
    public string? DeclaredCertificateReference { get; }

    public ProviderComplianceProfile(
        bool declaredValidatedBoundary,
        string? declaredModuleName,
        string? declaredCertificateReference)
    {
        DeclaredValidatedBoundary = declaredValidatedBoundary;
        DeclaredModuleName = string.IsNullOrWhiteSpace(declaredModuleName) ? null : declaredModuleName;
        DeclaredCertificateReference = string.IsNullOrWhiteSpace(declaredCertificateReference) ? null : declaredCertificateReference;
    }

    public static ProviderComplianceProfile FromEnvelope(ProviderComplianceEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);

        return new ProviderComplianceProfile(
            envelope.DeclaredValidatedBoundary,
            envelope.DeclaredModuleName,
            envelope.DeclaredCertificateReference);
    }

    public static ProviderComplianceProfile None { get; } =
        new(
            declaredValidatedBoundary: false,
            declaredModuleName: null,
            declaredCertificateReference: null);
}
