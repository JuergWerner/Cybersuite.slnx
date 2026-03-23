using System;
using System.Security.Cryptography;
using Cybersuite.Abstractions;

namespace Cybersuite.Policy;

/// <summary>
/// Immutable configuration for the <see cref="PolicyLoader"/> validation pipeline.
/// Wave 3 hardens non-Dev construction so staging and production paths are safe by construction.
/// </summary>
public sealed class PolicyLoadOptions
{
    public int MaxPolicyBytes { get; }
    public long MinimumAcceptedSequence { get; }
    public ExecutionProfile Profile { get; }

    /// <summary>
    /// If true, a signature must be present and verified, otherwise fail-closed.
    /// </summary>
    public bool RequireSignatureVerification { get; }

    /// <summary>
    /// If true, provider allowlist must be non-empty, otherwise fail-closed.
    /// </summary>
    public bool RequireProviderAllowlist { get; }

    /// <summary>
    /// Optional expected policy hash (SHA-384). If set, compared using FixedTimeEquals.
    /// </summary>
    public ReadOnlyMemory<byte> ExpectedPolicyHashSha384 { get; }

    public IPolicySignatureVerifier? SignatureVerifier { get; }
    public PolicySignatureVerificationOptions SignatureVerificationOptions { get; }

    public PolicyLoadOptions(
        ExecutionProfile profile,
        int maxPolicyBytes = 1024 * 1024,
        long minimumAcceptedSequence = 0,
        bool requireSignatureVerification = false,
        bool requireProviderAllowlist = false,
        ReadOnlyMemory<byte> expectedPolicyHashSha384 = default,
        IPolicySignatureVerifier? signatureVerifier = null,
        PolicySignatureVerificationOptions? signatureVerificationOptions = null)
    {
        if (maxPolicyBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxPolicyBytes));
        if (minimumAcceptedSequence < 0)
            throw new ArgumentOutOfRangeException(nameof(minimumAcceptedSequence));

        Profile = profile;
        MaxPolicyBytes = maxPolicyBytes;
        MinimumAcceptedSequence = minimumAcceptedSequence;
        RequireSignatureVerification = requireSignatureVerification;
        RequireProviderAllowlist = requireProviderAllowlist;
        ExpectedPolicyHashSha384 = expectedPolicyHashSha384;
        SignatureVerifier = signatureVerifier;
        SignatureVerificationOptions = signatureVerificationOptions
            ?? (profile switch
            {
                ExecutionProfile.Dev => PolicySignatureVerificationOptions.CreateDevRelaxed(),
                ExecutionProfile.Staging => throw new ArgumentException(
                    "Staging profile requires explicit strict PolicySignatureVerificationOptions. Use CreateStagingStrict(...).",
                    nameof(signatureVerificationOptions)),
                ExecutionProfile.Prod => throw new ArgumentException(
                    "Prod profile requires explicit strict PolicySignatureVerificationOptions. Use CreateProdStrict(...).",
                    nameof(signatureVerificationOptions)),
                _ => PolicySignatureVerificationOptions.CreateDevRelaxed()
            });

        ValidateSecurityProfile();
    }

    [Obsolete("ProductionDefault is retired. Use CreateProdStrict(...) instead.")]
    public static PolicyLoadOptions ProductionDefault =>
        throw new NotSupportedException("ProductionDefault is retired. Use CreateProdStrict(...) with a mandatory verifier.");

    public static PolicyLoadOptions CreateDevRelaxed(
        int maxPolicyBytes = 1024 * 1024,
        long minimumAcceptedSequence = 0,
        bool requireSignatureVerification = false,
        bool requireProviderAllowlist = false,
        ReadOnlyMemory<byte> expectedPolicyHashSha384 = default,
        IPolicySignatureVerifier? signatureVerifier = null,
        PolicySignatureVerificationOptions? signatureVerificationOptions = null)
    {
        return new PolicyLoadOptions(
            profile: ExecutionProfile.Dev,
            maxPolicyBytes: maxPolicyBytes,
            minimumAcceptedSequence: minimumAcceptedSequence,
            requireSignatureVerification: requireSignatureVerification,
            requireProviderAllowlist: requireProviderAllowlist,
            expectedPolicyHashSha384: expectedPolicyHashSha384,
            signatureVerifier: signatureVerifier,
            signatureVerificationOptions: signatureVerificationOptions ?? PolicySignatureVerificationOptions.CreateDevRelaxed());
    }

    public static PolicyLoadOptions CreateStagingStrict(
        IPolicySignatureVerifier signatureVerifier,
        PolicySignatureVerificationOptions? signatureVerificationOptions = null,
        int maxPolicyBytes = 1024 * 1024,
        long minimumAcceptedSequence = 0,
        ReadOnlyMemory<byte> expectedPolicyHashSha384 = default)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);

        return new PolicyLoadOptions(
            profile: ExecutionProfile.Staging,
            maxPolicyBytes: maxPolicyBytes,
            minimumAcceptedSequence: minimumAcceptedSequence,
            requireSignatureVerification: true,
            requireProviderAllowlist: true,
            expectedPolicyHashSha384: expectedPolicyHashSha384,
            signatureVerifier: signatureVerifier,
            signatureVerificationOptions: signatureVerificationOptions ?? PolicySignatureVerificationOptions.CreateStagingStrict());
    }

    public static PolicyLoadOptions CreateProdStrict(
        IPolicySignatureVerifier signatureVerifier,
        PolicySignatureVerificationOptions? signatureVerificationOptions = null,
        int maxPolicyBytes = 1024 * 1024,
        long minimumAcceptedSequence = 0,
        ReadOnlyMemory<byte> expectedPolicyHashSha384 = default)
    {
        ArgumentNullException.ThrowIfNull(signatureVerifier);

        return new PolicyLoadOptions(
            profile: ExecutionProfile.Prod,
            maxPolicyBytes: maxPolicyBytes,
            minimumAcceptedSequence: minimumAcceptedSequence,
            requireSignatureVerification: true,
            requireProviderAllowlist: true,
            expectedPolicyHashSha384: expectedPolicyHashSha384,
            signatureVerifier: signatureVerifier,
            signatureVerificationOptions: signatureVerificationOptions ?? PolicySignatureVerificationOptions.CreateProdStrict());
    }

    [Obsolete("CreateProductionDefault is renamed. Use CreateProdStrict(...) instead.")]
    public static PolicyLoadOptions CreateProductionDefault(
        IPolicySignatureVerifier signatureVerifier,
        PolicySignatureVerificationOptions? signatureVerificationOptions = null)
        => CreateProdStrict(signatureVerifier, signatureVerificationOptions);

    private void ValidateSecurityProfile()
    {
        SignatureVerificationOptions.ValidateForProfile(Profile);

        if (Profile == ExecutionProfile.Dev)
            return;

        if (!RequireSignatureVerification)
        {
            throw new ArgumentException(
                $"{Profile} profile requires signature verification. Use Create{Profile}Strict(...).",
                nameof(RequireSignatureVerification));
        }

        if (!RequireProviderAllowlist)
        {
            throw new ArgumentException(
                $"{Profile} profile requires a provider allowlist.",
                nameof(RequireProviderAllowlist));
        }

        if (SignatureVerifier is null)
        {
            throw new ArgumentNullException(
                nameof(SignatureVerifier),
                $"{Profile} profile requires a non-null signature verifier.");
        }
    }
}
