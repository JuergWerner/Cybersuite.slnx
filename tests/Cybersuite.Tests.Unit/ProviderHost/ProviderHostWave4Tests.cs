using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.OopProtocol.Session;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Discovery;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;
using Xunit;

using ProviderHostRuntime = Cybersuite.ProviderHost.ProviderHost;

namespace Cybersuite.Tests.Unit.ProviderHost;

public sealed class ProviderHostWave4Tests
{
    [Fact]
    public async Task StartAsync_ProdProductionIsolatedPackage_WithStructuredProvenanceAndAttestation_Accepts()
    {
        using var artifact = TempEntrypointArtifact.Create();
        const string signerFingerprint = "AA BB CC DD EE FF 00 11";

        ProviderPackage package = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            signerFingerprint);

        var connection = new FakeProductionConnection(package, includeAttestation: true);

        await using var host = new ProviderHostRuntime(
            options: CreateProdOptions(signerFingerprint),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: new DefaultProviderTrustEvaluator(),
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Prod,
            RequiredBoundaryClass.IsolatedProcess,
            experimentalAllowed: false,
            fipsRequired: false,
            attestationRequirement: AttestationRequirement.Required);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.Equal(ProviderHostLifecycleState.Started, host.LifecycleState);
        Assert.True(host.Snapshot.Providers.TryGetValue(package.Manifest.ProviderId, out ProviderRecord? record));
        Assert.NotNull(record);
        Assert.Equal(ProviderProvenanceStatus.StructuredValidated, record!.ProvenanceStatus);
        Assert.Equal(ProviderAttestationStatus.Verified, record.AttestationStatus);
        Assert.False(string.IsNullOrWhiteSpace(record.AttestationEvidenceSha256Hex));
    }

    [Fact]
    public async Task StartAsync_ProdProductionPackage_MissingStructuredProvenance_RejectedBeforeLaunch()
    {
        using var artifact = TempEntrypointArtifact.Create();
        const string signerFingerprint = "11 22 33 44 55";

        ProviderPackage accepted = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            signerFingerprint);

        ProviderPackage package = accepted with
        {
            Manifest = accepted.Manifest with
            {
                SignatureBundleBase64 = null
            }
        };

        var launcher = new TrackingLauncher(new FakeProductionConnection(package, includeAttestation: true));

        await using var host = new ProviderHostRuntime(
            options: CreateProdOptions(signerFingerprint),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: new DefaultProviderTrustEvaluator(),
            launcher: launcher,
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Prod,
            RequiredBoundaryClass.IsolatedProcess,
            experimentalAllowed: false,
            fipsRequired: false,
            attestationRequirement: AttestationRequirement.Optional);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.False(launcher.LaunchInvoked);
        Assert.Empty(host.Snapshot.Providers);
        Assert.Contains(
            host.FailureJournal.Entries,
            entry => entry.ReasonCode == ProviderHostReasonCodes.ProvenanceBundleMissing
                  && entry.State == ProviderLifecycleState.TrustRejected);
    }

    [Fact]
    public async Task StartAsync_AttestationRequiredAndMissing_RollsBackAfterLaunch()
    {
        using var artifact = TempEntrypointArtifact.Create();
        const string signerFingerprint = "66 77 88 99 AA";

        ProviderPackage package = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            signerFingerprint);

        var launcher = new TrackingLauncher(new FakeProductionConnection(package, includeAttestation: false));

        await using var host = new ProviderHostRuntime(
            options: CreateProdOptions(signerFingerprint),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: new DefaultProviderTrustEvaluator(),
            launcher: launcher,
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Prod,
            RequiredBoundaryClass.IsolatedProcess,
            experimentalAllowed: false,
            fipsRequired: false,
            attestationRequirement: AttestationRequirement.Required);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.True(launcher.LaunchInvoked);
        Assert.Empty(host.Snapshot.Providers);
        Assert.Contains(
            host.FailureJournal.Entries,
            entry => entry.ReasonCode == ProviderHostReasonCodes.AttestationRequiredMissing
                  && entry.State == ProviderLifecycleState.RolledBack);
    }

    [Fact]
    public async Task StartAsync_Prod_InProcessManifestWithProductionEnvelope_RejectedAsIsolationMismatch()
    {
        using var artifact = TempEntrypointArtifact.Create();

        ProviderComplianceEnvelope productionEnvelope = new(
            securityClass: ProviderSecurityClass.ProductionIsolated,
            boundaryClass: RequiredBoundaryClass.IsolatedProcess,
            declaredValidatedBoundary: false,
            declaredModuleName: "Cybersuite.Provider.BouncyCastle.Worker",
            declaredCertificateReference: null,
            declaredModuleVersion: "1.0.0",
            supportsNonExportableKeys: true,
            supportsRawSecretEgress: false,
            attestationMode: AttestationMode.Optional);

        ProviderPackage package = new()
        {
            PackageRoot = artifact.DirectoryPath,
            EntrypointPath = artifact.EntrypointPath,
            Manifest = new ProviderManifest
            {
                ProviderId = BouncyCastleProviderIds.ProviderId,
                Version = "1.0.0",
                Vendor = "Bouncy Castle",
                IsolationMode = ProviderIsolationMode.InProcess,
                IsExperimental = false,
                FipsBoundaryDeclared = false,
                ComplianceEnvelope = productionEnvelope,
                EntrypointSha256Hex = ComputeSha256Hex(artifact.EntrypointPath),
                SignatureBundleBase64 = null
            }
        };

        var launcher = new TrackingLauncher(new FakeProductionConnection(package, includeAttestation: true));

        await using var host = new ProviderHostRuntime(
            options: CreateProdOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: launcher,
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Prod,
            RequiredBoundaryClass.IsolatedProcess,
            experimentalAllowed: false,
            fipsRequired: false,
            attestationRequirement: AttestationRequirement.None);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.False(launcher.LaunchInvoked);
        Assert.Contains(
            host.FailureJournal.Entries,
            entry => entry.ReasonCode == ProviderHostReasonCodes.ManifestIsolationEnvelopeMismatch
                  && entry.State == ProviderLifecycleState.TrustRejected);
    }

    [Fact]
    public async Task BouncyCastleProviderConnection_ProductionIsolatedCatalog_DoesNotAdvertiseMlKem()
    {
        using var artifact = TempEntrypointArtifact.Create();

        ProviderPackage package = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            signerFingerprint: "AB CD EF 12 34");

        await using var connection = new BouncyCastleProviderConnection(package);

        ClientHello clientHello = CreateClientHello(ExecutionProfile.Prod, package.Manifest.ProviderId);
        ProviderHello providerHello = await connection.HandshakeAsync(clientHello, CancellationToken.None);
        OopSessionBinding binding = OopSessionBinding.Create(clientHello, providerHello);

        var header = new OopRequestHeader(
            version: ProtocolVersion.V1_0,
            messageType: OopMessageType.KemGenerateKeyPairRequest,
            requestId: Handle128.NewRandom(),
            messageCounter: 1,
            channelBindingSha384: binding.ChannelBindingSha384.Span);

        var ex = await Assert.ThrowsAsync<OopProtocolException>(async () =>
            await connection.KemGenerateKeyPairAsync(
                new KemGenerateKeyPairRequest(header, TestFixtures.MlKem768),
                CancellationToken.None));

        Assert.Contains("not advertised", ex.Message, StringComparison.OrdinalIgnoreCase);
    }


    [Fact]
    public void BouncyCastleLaunchHandler_ProductionIsolatedPackage_IsAdmittedByRealLaunchContext()
    {
        using var artifact = TempEntrypointArtifact.Create();

        ProviderPackage package = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            signerFingerprint: "00 11 22 33 44 55");

        var handler = new BouncyCastleLaunchHandler();
        ProviderLaunchContext context = new(
            Profile: ExecutionProfile.Prod,
            TargetSecurityClass: ProviderSecurityClass.ProductionIsolated,
            RequiredBoundaryClass: RequiredBoundaryClass.IsolatedProcess,
            TransportBudget: OopTransportBudget.ForProfile(ExecutionProfile.Prod, OopTransportLimits.Default),
            EnableNetworkAccess: false,
            BoundPolicyHashSha384: ImmutableArray.CreateRange(new byte[48]),
            ExpectedProviderId: package.Manifest.ProviderId,
            ExpectedBuildHashSha256: null);

        Assert.True(handler.CanLaunch(package, context));
    }

    private static ProviderHostOptions CreateProdOptions(string? signerFingerprint = null)
    {
        ImmutableHashSet<string> allowedSigners = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(signerFingerprint))
            allowedSigners = allowedSigners.Add(ProviderStructuredProvenanceBundle.NormalizeFingerprint(signerFingerprint));

        return new ProviderHostOptions
        {
            ExecutionProfile = ExecutionProfile.Prod,
            RequireNonEmptyAllowlistInProd = false,
            ProviderIdAllowlist = ImmutableHashSet<ProviderId>.Empty.Add(BouncyCastleProviderIds.ProviderId),
            AllowedProvenanceSignerFingerprints = allowedSigners,
            ProviderStartupTimeout = TimeSpan.FromSeconds(2),
            ProviderShutdownTimeout = TimeSpan.FromSeconds(1),
            EnableNetworkAccess = false,
            TransportLimits = OopTransportLimits.Default
        };
    }

    private static ProviderSessionBinding CreateBinding(
        ExecutionProfile profile,
        RequiredBoundaryClass requiredBoundaryClass,
        bool experimentalAllowed,
        bool fipsRequired,
        AttestationRequirement attestationRequirement)
    {
        EffectiveComplianceContext effective = new(
            profile: profile,
            policyHashSha384: new byte[48],
            tenantId: null,
            policyFipsRequired: fipsRequired,
            forceFips: null,
            experimentalAllowed: experimentalAllowed,
            requiredBoundaryClass: requiredBoundaryClass,
            requiredProviderIds: ImmutableHashSet<ProviderId>.Empty,
            requiredBuildHashes: ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
            attestationRequirement: attestationRequirement);

        return new ProviderSessionBinding
        {
            PolicyHashSha384 = effective.PolicyHashSha384,
            ExecutionProfile = profile,
            FipsRequired = fipsRequired,
            ExperimentalAllowed = experimentalAllowed,
            TenantId = null,
            ExpectedProviderId = null,
            ExpectedBuildHash = null,
            EffectiveCompliance = effective
        };
    }

    private static ClientHello CreateClientHello(ExecutionProfile profile, ProviderId providerId)
        => new(
            version: ProtocolVersion.V1_0,
            nonce32: new byte[OopConstants.NonceSizeBytes],
            policyHashSha384: new byte[48],
            profile: profile,
            fipsRequired: false,
            experimentalAllowed: false,
            tenantId: null,
            expectedProviderId: providerId.Value,
            expectedBuildHash: null);

    private static string ComputeSha256Hex(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var sha = System.Security.Cryptography.SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(stream));
    }

    private sealed class TempEntrypointArtifact : IDisposable
    {
        private TempEntrypointArtifact(string directoryPath, string entrypointPath)
        {
            DirectoryPath = directoryPath;
            EntrypointPath = entrypointPath;
        }

        public string DirectoryPath { get; }
        public string EntrypointPath { get; }

        public static TempEntrypointArtifact Create()
        {
            string directoryPath = Path.Combine(Path.GetTempPath(), "cybersuite-wave4-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directoryPath);

            string entrypointPath = Path.Combine(directoryPath, "provider-worker.dll");
            File.WriteAllBytes(entrypointPath, new byte[] { 0x43, 0x53, 0x57, 0x34, 0x10, 0x20, 0x30, 0x40 });

            return new TempEntrypointArtifact(directoryPath, entrypointPath);
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(DirectoryPath))
                    Directory.Delete(DirectoryPath, recursive: true);
            }
            catch
            {
                // best-effort cleanup
            }
        }
    }

    private sealed class SinglePackageDiscovery : IProviderDiscovery
    {
        private readonly ProviderPackage _package;

        public SinglePackageDiscovery(ProviderPackage package)
        {
            _package = package;
        }

        public async IAsyncEnumerable<ProviderPackage> DiscoverAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return _package;
            await Task.CompletedTask;
        }
    }

    private sealed class StaticLauncher : IProviderLauncher
    {
        private readonly IProviderConnection _connection;

        public StaticLauncher(IProviderConnection connection)
        {
            _connection = connection;
        }

        public ValueTask<IProviderConnection> LaunchAsync(ProviderPackage package, ProviderLaunchContext launchContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            launchContext.Validate();
            return ValueTask.FromResult(_connection);
        }
    }

    private sealed class TrackingLauncher : IProviderLauncher
    {
        private readonly IProviderConnection _connection;

        public TrackingLauncher(IProviderConnection connection)
        {
            _connection = connection;
        }

        public bool LaunchInvoked { get; private set; }

        public ValueTask<IProviderConnection> LaunchAsync(ProviderPackage package, ProviderLaunchContext launchContext, CancellationToken cancellationToken)
        {
            LaunchInvoked = true;
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(_connection);
        }
    }

    private sealed class AllowAllTrustEvaluator : IProviderTrustEvaluator
    {
        public static AllowAllTrustEvaluator Instance { get; } = new();

        public ValueTask<ProviderTrustDecision> EvaluateAsync(
            ProviderPackage package,
            ProviderHostOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ProviderTrustDecision(true, "trusted"));
        }
    }

    private sealed class FakeProductionConnection : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly CapabilitySnapshot _snapshot;
        private readonly ProviderComplianceEnvelope _envelope;
        private readonly byte[] _capabilityCanonicalBytes;
        private readonly byte[]? _attestationEvidence;
        private bool _disposed;

        public FakeProductionConnection(ProviderPackage package, bool includeAttestation)
        {
            _identity = new ProviderIdentity(
                package.Manifest.ProviderId,
                package.Manifest.Version,
                package.Manifest.EntrypointSha256Hex ?? throw new InvalidOperationException("Build hash is required."),
                signatureFingerprint: null);

            _snapshot = CapabilitySnapshot.Create(
                _identity,
                ImmutableArray.Create(
                    TestFixtures.Classical_KEM(package.Manifest.ProviderId),
                    TestFixtures.Classical_Sig(package.Manifest.ProviderId),
                    TestFixtures.Aead(package.Manifest.ProviderId),
                    TestFixtures.Kdf(package.Manifest.ProviderId)));

            _capabilityCanonicalBytes = _snapshot.GetCanonicalBytes();
            _envelope = package.Manifest.ComplianceEnvelope;

            if (includeAttestation)
            {
                _attestationEvidence = new ProviderStructuredAttestationStatement(
                    ProviderId: package.Manifest.ProviderId.Value,
                    BuildHashSha256Hex: _identity.BuildHash,
                    SecurityClass: _envelope.SecurityClass,
                    BoundaryClass: _envelope.BoundaryClass,
                    ModuleName: _envelope.DeclaredModuleName,
                    ModuleVersion: _envelope.DeclaredModuleVersion,
                    IssuedAtUtc: DateTimeOffset.UtcNow).ToUtf8Bytes();
            }
        }

        public ValueTask<ProviderHello> HandshakeAsync(ClientHello clientHello, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return ValueTask.FromResult(
                new ProviderHello(
                    version: ProtocolVersion.V1_0,
                    nonce32: new byte[OopConstants.NonceSizeBytes],
                    identity: _identity,
                    capabilityHashSha384: _snapshot.CapabilityHashSha384.Span,
                    complianceEnvelope: _envelope,
                    isExperimental: false,
                    attestationEvidence: _attestationEvidence));
        }

        public ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return ValueTask.FromResult(
                new CapabilityResponse(
                    SuccessHeader(request.Header, OopMessageType.CapabilityResponse),
                    _capabilityCanonicalBytes,
                    _snapshot.CapabilityHashSha384.Span));
        }

        public ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken)
            => ValueTask.FromResult(new HealthResponse(SuccessHeader(request.Header, OopMessageType.HealthResponse), isHealthy: true));

        public ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
            => ValueTask.FromResult(new ShutdownResponse(SuccessHeader(request.Header, OopMessageType.ShutdownResponse)));

        public ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<KemEncapsulateResponse> KemEncapsulateAsync(KemEncapsulateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<KemDecapsulateResponse> KemDecapsulateAsync(KemDecapsulateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<SignatureVerifyResponse> SignatureVerifyAsync(SignatureVerifyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<AeadGenerateKeyResponse> AeadGenerateKeyAsync(AeadGenerateKeyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<AeadEncryptResponse> AeadEncryptAsync(AeadEncryptRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<AeadDecryptResponse> AeadDecryptAsync(AeadDecryptRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<KdfDeriveKeyResponse> KdfDeriveKeyAsync(KdfDeriveKeyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<DestroyHandleResponse> DestroyHandleAsync(DestroyHandleRequest request, CancellationToken cancellationToken)
            => ValueTask.FromResult(new DestroyHandleResponse(SuccessHeader(request.Header, OopMessageType.DestroyHandleResponse)));

        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        private static OopResponseHeader SuccessHeader(OopRequestHeader header, OopMessageType responseType)
            => new(
                version: header.Version,
                messageType: responseType,
                requestId: header.RequestId,
                messageCounter: header.MessageCounter,
                channelBindingSha384: header.ChannelBindingSha384.Span,
                success: true,
                error: null);
    }
}
