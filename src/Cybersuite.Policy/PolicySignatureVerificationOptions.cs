using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using Cybersuite.Abstractions;

namespace Cybersuite.Policy;

/// <summary>
/// Verification inputs are non-secret. Avoid system-global mutable trust configuration.
/// Wave 3 introduces explicit relaxed/strict factory paths so staging and production
/// cannot accidentally inherit weak revocation or untrusted-chain defaults.
/// </summary>
public sealed class PolicySignatureVerificationOptions
{
    /// <summary>
    /// If provided, use CustomRootTrust with these DER roots. If empty, system trust is used.
    /// </summary>
    public ImmutableArray<ReadOnlyMemory<byte>> TrustedRootsDer { get; }

    /// <summary>
    /// Optional allowlist of signer certificate thumbprints (uppercase, hex, no spaces).
    /// Empty => no thumbprint allowlist check.
    /// </summary>
    public ImmutableHashSet<string> AllowedSignerThumbprints { get; }

    /// <summary>
    /// If true, a chain build failure is tolerated (DEV only).
    /// </summary>
    public bool AllowUntrustedChainInDevOnly { get; }

    /// <summary>
    /// X.509 certificate revocation checking mode.
    /// </summary>
    public X509RevocationMode RevocationMode { get; }

    public PolicySignatureVerificationOptions(
        ImmutableArray<ReadOnlyMemory<byte>> trustedRootsDer,
        ImmutableHashSet<string>? allowedSignerThumbprints,
        bool allowUntrustedChainInDevOnly,
        X509RevocationMode revocationMode = X509RevocationMode.NoCheck)
    {
        TrustedRootsDer = trustedRootsDer.IsDefault
            ? ImmutableArray<ReadOnlyMemory<byte>>.Empty
            : trustedRootsDer;
        AllowedSignerThumbprints = allowedSignerThumbprints ?? ImmutableHashSet<string>.Empty;
        AllowUntrustedChainInDevOnly = allowUntrustedChainInDevOnly;
        RevocationMode = revocationMode;
    }

    /// <summary>
    /// Backward-compatible relaxed default. Suitable for development only.
    /// </summary>
    public static PolicySignatureVerificationOptions Default =>
        CreateDevRelaxed();

    public static PolicySignatureVerificationOptions CreateDevRelaxed(
        ImmutableArray<ReadOnlyMemory<byte>> trustedRootsDer = default,
        ImmutableHashSet<string>? allowedSignerThumbprints = null,
        bool allowUntrustedChainInDevOnly = false,
        X509RevocationMode revocationMode = X509RevocationMode.NoCheck)
    {
        return new PolicySignatureVerificationOptions(
            trustedRootsDer: trustedRootsDer.IsDefault ? ImmutableArray<ReadOnlyMemory<byte>>.Empty : trustedRootsDer,
            allowedSignerThumbprints: allowedSignerThumbprints ?? ImmutableHashSet<string>.Empty,
            allowUntrustedChainInDevOnly: allowUntrustedChainInDevOnly,
            revocationMode: revocationMode);
    }

    public static PolicySignatureVerificationOptions CreateStagingStrict(
        ImmutableArray<ReadOnlyMemory<byte>> trustedRootsDer = default,
        ImmutableHashSet<string>? allowedSignerThumbprints = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        EnsureStrictRevocationMode(revocationMode, ExecutionProfile.Staging);

        return new PolicySignatureVerificationOptions(
            trustedRootsDer: trustedRootsDer.IsDefault ? ImmutableArray<ReadOnlyMemory<byte>>.Empty : trustedRootsDer,
            allowedSignerThumbprints: allowedSignerThumbprints ?? ImmutableHashSet<string>.Empty,
            allowUntrustedChainInDevOnly: false,
            revocationMode: revocationMode);
    }

    public static PolicySignatureVerificationOptions CreateProdStrict(
        ImmutableArray<ReadOnlyMemory<byte>> trustedRootsDer = default,
        ImmutableHashSet<string>? allowedSignerThumbprints = null,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        EnsureStrictRevocationMode(revocationMode, ExecutionProfile.Prod);

        return new PolicySignatureVerificationOptions(
            trustedRootsDer: trustedRootsDer.IsDefault ? ImmutableArray<ReadOnlyMemory<byte>>.Empty : trustedRootsDer,
            allowedSignerThumbprints: allowedSignerThumbprints ?? ImmutableHashSet<string>.Empty,
            allowUntrustedChainInDevOnly: false,
            revocationMode: revocationMode);
    }

    public void ValidateForProfile(ExecutionProfile profile)
    {
        if (profile == ExecutionProfile.Dev)
            return;

        if (AllowUntrustedChainInDevOnly)
        {
            throw new ArgumentException(
                "AllowUntrustedChainInDevOnly may only be enabled in Dev profile.",
                nameof(AllowUntrustedChainInDevOnly));
        }

        EnsureStrictRevocationMode(RevocationMode, profile);
    }

    private static void EnsureStrictRevocationMode(X509RevocationMode revocationMode, ExecutionProfile profile)
    {
        if (revocationMode == X509RevocationMode.NoCheck)
        {
            throw new ArgumentException(
                $"RevocationMode.NoCheck is not allowed in {profile} profile. Use Online or Offline revocation.",
                nameof(revocationMode));
        }
    }
}
