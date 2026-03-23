using System;
using System.IO;
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Microsoft.Extensions.Logging;

namespace Cybersuite.Policy;

/// <summary>
/// Loads and validates policy JSON into an immutable <see cref="PolicySnapshot"/>.
/// Validation is fail-closed and profile-aware.
/// </summary>
public static class PolicyLoader
{
    public static PolicySnapshot LoadFromFile(string path, PolicyLoadOptions options, ILogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new ArgumentException("Path required.", nameof(path));

        ArgumentNullException.ThrowIfNull(options);

        // SEC-M-003: Check file size before loading to prevent DoS via oversized files.
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            throw new PolicyValidationException($"Policy file not found: {path}");

        if (fileInfo.Length > options.MaxPolicyBytes)
            throw new PolicyValidationException("Policy file exceeds MaxPolicyBytes.");

        byte[] bytes = File.ReadAllBytes(path);
        logger?.LogDebug("Policy file loaded — {Bytes} bytes from {Path}", bytes.Length, path);
        return LoadFromBytes(bytes, options, logger);
    }

    public static PolicySnapshot LoadFromBytes(ReadOnlySpan<byte> policyUtf8, PolicyLoadOptions options, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (policyUtf8.Length <= 0)
            throw new PolicyValidationException("Policy is empty.");

        if (policyUtf8.Length > options.MaxPolicyBytes)
            throw new PolicyValidationException("Policy exceeds MaxPolicyBytes.");

        // Wave 3: enforce profile-consistent policy verification semantics before parsing further.
        ValidateProfileSecurityOptions(options);

        // Parse model (includes signature envelope if present)
        var model = PolicyJsonParser.Parse(policyUtf8);
        logger?.LogDebug("Policy parsed — schema={Schema}, sequence={Sequence}, mode={Mode}",
            model.SchemaVersion, model.Sequence, model.SecurityMode);

        if (model.Sequence < options.MinimumAcceptedSequence)
            throw new PolicyValidationException("Policy sequence is below minimum accepted sequence (anti-rollback).");

        // Canonicalize excluding signature field
        byte[] canonical = PolicyCanonicalizer.CanonicalizePolicyUtf8(policyUtf8);

        // Hash canonical bytes (SHA-384)
        byte[] hash = SHA384.HashData(canonical);

        // Optional expected hash gate (constant-time)
        if (!options.ExpectedPolicyHashSha384.IsEmpty)
        {
            if (options.ExpectedPolicyHashSha384.Length != hash.Length)
                throw new PolicyValidationException("ExpectedPolicyHashSha384 length mismatch.");

            if (!CryptographicOperations.FixedTimeEquals(options.ExpectedPolicyHashSha384.Span, hash))
                throw new PolicyValidationException("Policy hash does not match expected hash.");
        }

        // Provider allowlist gate (profile-driven)
        if (options.RequireProviderAllowlist && model.ProviderAllowlist.Length == 0)
            throw new PolicyValidationException("Provider allowlist required but missing/empty.");

        // Signature gate (profile-driven)
        if (options.RequireSignatureVerification)
        {
            if (model.Signature is null)
                throw new PolicyValidationException("Signature required but not present in policy.");

            if (options.SignatureVerifier is null)
                throw new PolicyValidationException("SignatureVerifier required but not provided.");

            if (!options.SignatureVerifier.Verify(canonical, model.Signature, options.SignatureVerificationOptions, out var reason))
                throw new PolicyValidationException($"Signature verification failed: {reason ?? "unknown"}");
        }

        // Produce immutable snapshot
        var snapshot = new PolicySnapshot(
            schemaVersion: model.SchemaVersion,
            sequence: model.Sequence,
            tenantId: model.TenantId,
            securityMode: model.SecurityMode,
            fipsRequired: model.FipsRequired,
            minimumStrengthByCategory: model.MinStrengthByCategory,
            providerAllowlist: model.ProviderAllowlist,
            pinnedProviderByCategory: model.PinnedProviderByCategory,
            pinnedProviderByAlgorithm: model.PinnedProviderByAlgorithm,
            policyHash: hash);

        logger?.LogInformation(
            "Policy snapshot created — sequence={Sequence}, mode={Mode}, allowlist={AllowlistCount} provider(s)",
            model.Sequence, model.SecurityMode, model.ProviderAllowlist.Length);

        return snapshot;
    }

    private static void ValidateProfileSecurityOptions(PolicyLoadOptions options)
    {
        if (options.Profile == ExecutionProfile.Dev)
            return;

        if (!options.RequireSignatureVerification)
            throw new PolicyValidationException($"{options.Profile} profile requires signature verification.");

        if (!options.RequireProviderAllowlist)
            throw new PolicyValidationException($"{options.Profile} profile requires a non-empty provider allowlist.");

        if (options.SignatureVerifier is null)
            throw new PolicyValidationException($"{options.Profile} profile requires a signature verifier.");

        try
        {
            options.SignatureVerificationOptions.ValidateForProfile(options.Profile);
        }
        catch (ArgumentException ex)
        {
            throw new PolicyValidationException(ex.Message, ex);
        }
    }
}
