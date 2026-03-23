namespace Cybersuite.Abstractions;

/// <summary>
/// Canonical attestation requirement transported alongside the effective compliance context.
/// Wave 1 keeps attestation inactive by default but carries the requirement explicitly so later
/// waves can enforce it without re-framing the runtime contract.
/// </summary>
public enum AttestationRequirement
{
    /// <summary>No attestation required. Default for Dev profile and current wave.</summary>
    None = 0,

    /// <summary>Attestation is requested but not enforced. Provider may supply a self-attestation statement.</summary>
    Optional = 1,

    /// <summary>
    /// Attestation is mandatory. The ProviderHost will reject providers that fail to supply a valid
    /// structured attestation statement during the trust evaluation pipeline (Wave 4+).
    /// </summary>
    Required = 2
}
