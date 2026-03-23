using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

public readonly record struct ProviderAttestationVerificationResult(
    bool IsAccepted,
    ProviderAttestationStatus Status,
    string Reason,
    string? EvidenceSha256Hex)
{
    public static ProviderAttestationVerificationResult Accepted(
        ProviderAttestationStatus status,
        string reason,
        string? evidenceSha256Hex = null)
        => new(true, status, reason, evidenceSha256Hex);

    public static ProviderAttestationVerificationResult Rejected(
        ProviderAttestationStatus status,
        string reason,
        string? evidenceSha256Hex = null)
        => new(false, status, reason, evidenceSha256Hex);
}
