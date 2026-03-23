namespace Cybersuite.ProviderModel;

/// <summary>
/// Result of provider attestation evidence evaluation.
/// Wave 4 activates structured self-attestation / allowlist enforcement without claiming
/// hardware-backed remote attestation where none exists.
/// </summary>
public enum ProviderAttestationStatus
{
    /// <summary>Attestation was not required for this evaluation context.</summary>
    NotRequired = 0,

    /// <summary>Attestation evidence was presented by the provider but not yet fully verified.</summary>
    Presented = 1,

    /// <summary>Attestation evidence was presented and successfully verified against the allowlist.</summary>
    Verified = 2,

    /// <summary>Attestation was required but the provider did not supply evidence.</summary>
    Missing = 3,

    /// <summary>Attestation evidence was presented but failed verification.</summary>
    Rejected = 4
}
