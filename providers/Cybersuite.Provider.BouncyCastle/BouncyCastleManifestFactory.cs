using System;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Org.BouncyCastle.Security;
using Cybersuite.Abstractions;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Helper for creating provider packages for the managed Bouncy Castle provider.
/// Wave 5 keeps the truthful split between the Dev/reference path and the classical-only
/// production-isolated path, and adds structured source-release metadata for non-Dev packages.
/// </summary>
public static class BouncyCastleManifestFactory
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false
    };

    /// <summary>
    /// Development default for post-quantum experimentation: Dev/reference + experimental PQC catalog.
    /// </summary>
    public static ProviderPackage CreateDevelopmentPqmPackage(
        string packageRoot,
        string entrypointPath)
        => CreateInProcessPackage(packageRoot, entrypointPath);

    public static ProviderPackage CreateInProcessPackage(
        string packageRoot,
        string entrypointPath)
    {
        ValidatePackagePaths(packageRoot, entrypointPath);

        string version = typeof(SecureRandom).Assembly.GetName().Version?.ToString() ?? "unknown";
        string buildHashHex = ComputeSha256Hex(entrypointPath);

        return new ProviderPackage
        {
            PackageRoot = packageRoot,
            EntrypointPath = entrypointPath,
            Manifest = new ProviderManifest
            {
                ProviderId = BouncyCastleProviderIds.ProviderId,
                Version = version,
                Vendor = "Bouncy Castle",
                IsolationMode = ProviderIsolationMode.InProcess,
                IsExperimental = true,
                FipsBoundaryDeclared = false,
                ComplianceEnvelope = ProviderComplianceEnvelope.ReferenceInProcessDefault,
                EntrypointSha256Hex = buildHashHex,
                SignatureBundleBase64 = null,
                ReleaseBundleBase64 = null
            }
        };
    }

    public static ProviderPackage CreateProductionIsolatedPackage(
        string packageRoot,
        string workerEntrypointPath,
        string signerFingerprint,
        DateTimeOffset? issuedAtUtc = null,
        DateTimeOffset? expiresAtUtc = null,
        string sourceRepository = "https://cybersuite.local/source",
        string releaseChannel = "prod-source")
    {
        ValidatePackagePaths(packageRoot, workerEntrypointPath);

        if (string.IsNullOrWhiteSpace(signerFingerprint))
            throw new ArgumentException("Signer fingerprint is required.", nameof(signerFingerprint));
        if (string.IsNullOrWhiteSpace(sourceRepository))
            throw new ArgumentException("Source repository is required.", nameof(sourceRepository));
        if (string.IsNullOrWhiteSpace(releaseChannel))
            throw new ArgumentException("Release channel is required.", nameof(releaseChannel));

        string version = typeof(SecureRandom).Assembly.GetName().Version?.ToString() ?? "unknown";
        string buildHashHex = ComputeSha256Hex(workerEntrypointPath);
        string normalizedFingerprint = ProviderStructuredProvenanceBundle.NormalizeFingerprint(signerFingerprint);
        string normalizedRepository = ProviderStructuredReleaseBundle.NormalizeRepository(sourceRepository);
        DateTimeOffset effectiveIssuedAt = issuedAtUtc ?? DateTimeOffset.UtcNow;
        DateTimeOffset effectiveExpiresAt = expiresAtUtc ?? DateTimeOffset.UtcNow.AddDays(30);

        ProviderComplianceEnvelope envelope = new(
            securityClass: ProviderSecurityClass.ProductionIsolated,
            boundaryClass: RequiredBoundaryClass.IsolatedProcess,
            declaredValidatedBoundary: false,
            declaredModuleName: "Cybersuite.Provider.BouncyCastle.Worker",
            declaredCertificateReference: null,
            declaredModuleVersion: version,
            supportsNonExportableKeys: true,
            supportsRawSecretEgress: false,
            attestationMode: AttestationMode.Optional);

        ProviderStructuredProvenanceBundle provenanceBundle = new(
            ProviderId: BouncyCastleProviderIds.ProviderId.Value,
            EntrypointSha256Hex: buildHashHex,
            SecurityClass: envelope.SecurityClass,
            BoundaryClass: envelope.BoundaryClass,
            ModuleName: envelope.DeclaredModuleName,
            ModuleVersion: envelope.DeclaredModuleVersion,
            SignerFingerprint: normalizedFingerprint,
            IssuedAtUtc: effectiveIssuedAt,
            ExpiresAtUtc: effectiveExpiresAt);

        byte[] releaseManifestBytes = CreateReleaseManifestBytes(
            providerId: BouncyCastleProviderIds.ProviderId.Value,
            version: version,
            buildHashHex: buildHashHex,
            sourceRepository: normalizedRepository,
            releaseChannel: releaseChannel,
            securityClass: envelope.SecurityClass,
            boundaryClass: envelope.BoundaryClass,
            issuedAtUtc: effectiveIssuedAt,
            signerFingerprint: normalizedFingerprint);

        byte[] sbomBytes = CreateSbomBytes(
            providerId: BouncyCastleProviderIds.ProviderId.Value,
            version: version,
            buildHashHex: buildHashHex,
            sourceRepository: normalizedRepository,
            releaseChannel: releaseChannel,
            moduleName: envelope.DeclaredModuleName,
            moduleVersion: envelope.DeclaredModuleVersion,
            entrypointPath: workerEntrypointPath);

        TryWriteReleaseArtifact(packageRoot, "provider-release.manifest.json", releaseManifestBytes);
        TryWriteReleaseArtifact(packageRoot, "provider-release.sbom.json", sbomBytes);

        ProviderStructuredReleaseBundle releaseBundle = new(
            ProviderId: BouncyCastleProviderIds.ProviderId.Value,
            EntrypointSha256Hex: buildHashHex,
            SecurityClass: envelope.SecurityClass,
            BoundaryClass: envelope.BoundaryClass,
            ReleaseVersion: version,
            ReleaseChannel: releaseChannel,
            SourceRepository: normalizedRepository,
            ReleaseManifestSha256Hex: ComputeSha256Hex(releaseManifestBytes),
            SbomSha256Hex: ComputeSha256Hex(sbomBytes),
            SignerFingerprint: normalizedFingerprint,
            IssuedAtUtc: effectiveIssuedAt,
            ExpiresAtUtc: effectiveExpiresAt);

        return new ProviderPackage
        {
            PackageRoot = packageRoot,
            EntrypointPath = workerEntrypointPath,
            Manifest = new ProviderManifest
            {
                ProviderId = BouncyCastleProviderIds.ProviderId,
                Version = version,
                Vendor = "Bouncy Castle",
                IsolationMode = ProviderIsolationMode.OutOfProcess,
                IsExperimental = false,
                FipsBoundaryDeclared = false,
                ComplianceEnvelope = envelope,
                EntrypointSha256Hex = buildHashHex,
                SignatureBundleBase64 = provenanceBundle.ToBase64(),
                ReleaseBundleBase64 = releaseBundle.ToBase64()
            }
        };
    }

    private static void ValidatePackagePaths(string packageRoot, string entrypointPath)
    {
        if (string.IsNullOrWhiteSpace(packageRoot))
            throw new ArgumentException("Package root is required.", nameof(packageRoot));
        if (string.IsNullOrWhiteSpace(entrypointPath))
            throw new ArgumentException("Entrypoint path is required.", nameof(entrypointPath));
        if (!File.Exists(entrypointPath))
            throw new FileNotFoundException("Entrypoint assembly not found.", entrypointPath);
    }

    private static byte[] CreateReleaseManifestBytes(
        string providerId,
        string version,
        string buildHashHex,
        string sourceRepository,
        string releaseChannel,
        ProviderSecurityClass securityClass,
        RequiredBoundaryClass boundaryClass,
        DateTimeOffset issuedAtUtc,
        string signerFingerprint)
        => JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                providerId,
                version,
                buildHashSha256Hex = buildHashHex,
                sourceRepository,
                releaseChannel,
                securityClass,
                boundaryClass,
                issuedAtUtc,
                signerFingerprint,
                generator = "BouncyCastleManifestFactory/Wave5"
            },
            JsonOptions);

    private static byte[] CreateSbomBytes(
        string providerId,
        string version,
        string buildHashHex,
        string sourceRepository,
        string releaseChannel,
        string? moduleName,
        string? moduleVersion,
        string entrypointPath)
        => JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                spdxVersion = "SPDX-2.3",
                dataLicense = "CC0-1.0",
                name = $"{providerId}-{version}",
                documentNamespace = $"urn:cybersuite:sbom:{providerId}:{version}",
                creationInfo = new
                {
                    created = DateTimeOffset.UtcNow,
                    creators = new[] { "Tool:Cybersuite Wave5 SBOM Emitter" }
                },
                packageName = moduleName ?? providerId,
                packageVersion = moduleVersion ?? version,
                sourceRepository,
                releaseChannel,
                files = new[]
                {
                    new
                    {
                        path = Path.GetFileName(entrypointPath),
                        sha256 = buildHashHex
                    }
                }
            },
            JsonOptions);

    private static void TryWriteReleaseArtifact(string packageRoot, string fileName, byte[] content)
    {
        try
        {
            string releaseDir = Path.Combine(packageRoot, "release");
            Directory.CreateDirectory(releaseDir);
            File.WriteAllBytes(Path.Combine(releaseDir, fileName), content);
        }
        catch
        {
            // best-effort packaging aid only; runtime verification binds to the digests in the release bundle.
        }
    }

    private static string ComputeSha256Hex(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(stream);
        try
        {
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static string ComputeSha256Hex(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        try
        {
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }
}
