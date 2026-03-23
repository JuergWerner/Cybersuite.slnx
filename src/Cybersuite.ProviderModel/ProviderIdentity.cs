using System;
using System.Text;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderModel;

/// <summary>
/// Immutable provider identity used for binding, auditing, trust evaluation, and session establishment.
/// Exchanged during the OPP handshake (ProviderHello) and embedded in provider manifests.
/// All string properties are normalized to Unicode NFC form for deterministic comparison and hashing.
/// </summary>
public sealed class ProviderIdentity
{
    /// <summary>Unique provider identifier (e.g. "BouncyCastle"). Must be non-empty.</summary>
    public ProviderId ProviderId { get; }

    /// <summary>Provider version string (e.g. "2.7.0-beta.98"). Must be non-empty. NFC-normalized.</summary>
    public string Version { get; }

    /// <summary>Build hash of the provider entrypoint binary (e.g. SHA-256 hex). Must be non-empty. NFC-normalized.</summary>
    public string BuildHash { get; }

    /// <summary>
    /// Optional fingerprint for provider package signature/certificate (format is implementation-defined).
    /// </summary>
    public string? SignatureFingerprint { get; }

    public ProviderIdentity(
        ProviderId providerId,
        string version,
        string buildHash,
        string? signatureFingerprint)
    {
        if (string.IsNullOrWhiteSpace(providerId.Value))
            throw new ArgumentException("ProviderId.Value must be non-empty.", nameof(providerId));
        if (string.IsNullOrWhiteSpace(version))
            throw new ArgumentException("Version must be non-empty.", nameof(version));
        if (string.IsNullOrWhiteSpace(buildHash))
            throw new ArgumentException("BuildHash must be non-empty.", nameof(buildHash));

        ProviderId = providerId;
        Version = version.Normalize(NormalizationForm.FormC);
        BuildHash = buildHash.Normalize(NormalizationForm.FormC);
        SignatureFingerprint = signatureFingerprint?.Normalize(NormalizationForm.FormC);
    }
}