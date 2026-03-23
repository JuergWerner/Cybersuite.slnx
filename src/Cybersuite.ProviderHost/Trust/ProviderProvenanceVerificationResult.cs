using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

public readonly record struct ProviderProvenanceVerificationResult(
    bool IsAccepted,
    ProviderProvenanceStatus Status,
    string Reason,
    string? SignerFingerprint)
{
    public static ProviderProvenanceVerificationResult Accepted(
        ProviderProvenanceStatus status,
        string reason,
        string? signerFingerprint = null)
        => new(true, status, reason, signerFingerprint);

    public static ProviderProvenanceVerificationResult Rejected(
        ProviderProvenanceStatus status,
        string reason,
        string? signerFingerprint = null)
        => new(false, status, reason, signerFingerprint);
}
