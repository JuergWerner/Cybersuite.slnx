using System.Text;

namespace Cybersuite.ProviderModel;

/// <summary>
/// Immutable provider metadata stored in the provider registry.
/// Combines the provider's <see cref="ProviderIdentity"/>, isolation mode, trust state,
/// and compliance declarations into a single registry-friendly record.
/// Created during provider startup and frozen for the provider's lifetime in the registry.
/// </summary>
public sealed class ProviderMetadata
{
    /// <summary>Authenticated provider identity (ID, version, build hash, signature fingerprint).</summary>
    public ProviderIdentity Identity { get; }

    /// <summary>Vendor name for audit and display purposes. NFC-normalized.</summary>
    public string Vendor { get; }

    /// <summary>Process-level isolation mode (InProcess / OutOfProcess / HardwareBoundary).</summary>
    public ProviderIsolationMode IsolationMode { get; }

    /// <summary>Current trust state as evaluated by the ProviderHost trust pipeline.</summary>
    public ProviderTrustState TrustState { get; }

    /// <summary>Whether this provider advertises experimental (non-Stable) capabilities.</summary>
    public bool IsExperimental { get; }

    /// <summary>
    /// Canonical provider-side compliance envelope bound into manifest and handshake.
    /// </summary>
    public ProviderComplianceEnvelope ComplianceEnvelope { get; }

    /// <summary>
    /// Legacy compatibility view over <see cref="ComplianceEnvelope"/>.
    /// </summary>
    public ProviderComplianceProfile ComplianceProfile { get; }

    public ProviderMetadata(
        ProviderIdentity identity,
        string vendor,
        ProviderIsolationMode isolationMode,
        ProviderTrustState trustState,
        bool isExperimental,
        ProviderComplianceProfile? complianceProfile = null)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        Vendor = (vendor ?? string.Empty).Normalize(NormalizationForm.FormC);
        IsolationMode = isolationMode;
        TrustState = trustState;
        IsExperimental = isExperimental;

        ComplianceProfile = complianceProfile ?? ProviderComplianceProfile.None;
        ComplianceEnvelope = ProviderComplianceEnvelope.FromLegacyProfile(IsolationMode, ComplianceProfile);
    }

    public ProviderMetadata(
        ProviderIdentity identity,
        string vendor,
        ProviderIsolationMode isolationMode,
        ProviderTrustState trustState,
        bool isExperimental,
        ProviderComplianceEnvelope complianceEnvelope,
        ProviderComplianceProfile? complianceProfile = null)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        Vendor = (vendor ?? string.Empty).Normalize(NormalizationForm.FormC);
        IsolationMode = isolationMode;
        TrustState = trustState;
        IsExperimental = isExperimental;
        ComplianceEnvelope = complianceEnvelope ?? throw new ArgumentNullException(nameof(complianceEnvelope));
        ComplianceProfile = complianceProfile ?? ProviderComplianceProfile.FromEnvelope(complianceEnvelope);
    }
}
