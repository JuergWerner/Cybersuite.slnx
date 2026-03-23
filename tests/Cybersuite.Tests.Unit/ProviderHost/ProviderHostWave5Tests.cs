using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Discovery;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;
using Xunit;

using ProviderHostRuntime = Cybersuite.ProviderHost.ProviderHost;

namespace Cybersuite.Tests.Unit.ProviderHost;

public sealed class ProviderHostWave5Tests
{
    private const string SourceRepository = "https://cybersuite.local/source";
    private const string ReleaseChannel = "prod-source";
    private const string SignerFingerprint = "DE AD BE EF 01 02 03 04";

    [Fact]
    public async Task StartAsync_ProdPackage_MissingStructuredReleaseBundle_RejectedBeforeLaunch()
    {
        using var artifact = Wave5TempEntrypointArtifact.Create();

        ProviderPackage accepted = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            SignerFingerprint,
            sourceRepository: SourceRepository,
            releaseChannel: ReleaseChannel);

        ProviderPackage package = accepted with
        {
            Manifest = accepted.Manifest with
            {
                ReleaseBundleBase64 = null
            }
        };

        var launcher = new Wave5TrackingLauncher(new Wave5FakeProductionConnection(package, includeAttestation: true));

        await using var host = new ProviderHostRuntime(
            options: CreateProdOptions(),
            discovery: new Wave5SinglePackageDiscovery(package),
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
            entry => entry.ReasonCode == ProviderHostReasonCodes.ReleaseBundleMissing
                  && entry.State == ProviderLifecycleState.TrustRejected);
    }

    [Fact]
    public async Task StartAsync_ProdPackage_WithStructuredReleaseBundle_AcceptsAndPersistsReleaseStatus()
    {
        using var artifact = Wave5TempEntrypointArtifact.Create();

        ProviderPackage package = BouncyCastleManifestFactory.CreateProductionIsolatedPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath,
            SignerFingerprint,
            sourceRepository: SourceRepository,
            releaseChannel: ReleaseChannel);

        var launcher = new Wave5StaticLauncher(new Wave5FakeProductionConnection(package, includeAttestation: true));

        await using var host = new ProviderHostRuntime(
            options: CreateProdOptions(),
            discovery: new Wave5SinglePackageDiscovery(package),
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

        Assert.Equal(ProviderHostLifecycleState.Started, host.LifecycleState);
        Assert.True(host.Snapshot.Providers.TryGetValue(package.Manifest.ProviderId, out ProviderRecord? record));
        Assert.NotNull(record);
        Assert.Equal(ProviderReleaseStatus.StructuredValidated, record!.ReleaseStatus);
        Assert.Equal(SourceRepository, record.ReleaseRepositoryUri);
        Assert.Equal(ReleaseChannel, record.ReleaseChannel);
        Assert.Equal(ProviderStructuredReleaseBundle.NormalizeFingerprint(SignerFingerprint), record.ReleaseSignerFingerprint);
        Assert.False(string.IsNullOrWhiteSpace(record.ReleaseManifestSha256Hex));
        Assert.False(string.IsNullOrWhiteSpace(record.ReleaseSbomSha256Hex));
    }

    [Fact]
    public void CreateDevelopmentPqmPackage_UsesReferenceInProcessExperimentalManifest()
    {
        using var artifact = Wave5TempEntrypointArtifact.Create();

        ProviderPackage package = BouncyCastleManifestFactory.CreateDevelopmentPqmPackage(
            artifact.DirectoryPath,
            artifact.EntrypointPath);

        Assert.Equal(ProviderIsolationMode.InProcess, package.Manifest.IsolationMode);
        Assert.True(package.Manifest.IsExperimental);
        Assert.Equal(ProviderSecurityClass.ReferenceInProcess, package.Manifest.ComplianceEnvelope.SecurityClass);
        Assert.Equal(RequiredBoundaryClass.None, package.Manifest.ComplianceEnvelope.BoundaryClass);
        Assert.Null(package.Manifest.ReleaseBundleBase64);
    }

    private static ProviderHostOptions CreateProdOptions()
        => new()
        {
            ExecutionProfile = ExecutionProfile.Prod,
            RequireNonEmptyAllowlistInProd = false,
            ProviderIdAllowlist = ImmutableHashSet<ProviderId>.Empty.Add(BouncyCastleProviderIds.ProviderId),
            AllowedProvenanceSignerFingerprints = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase)
                .Add(ProviderStructuredProvenanceBundle.NormalizeFingerprint(SignerFingerprint)),
            AllowedReleaseRepositoryUris = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase)
                .Add(ProviderStructuredReleaseBundle.NormalizeRepository(SourceRepository)),
            AllowedReleaseChannels = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase)
                .Add(ReleaseChannel),
            AllowedReleaseSignerFingerprints = ImmutableHashSet<string>.Empty.WithComparer(StringComparer.OrdinalIgnoreCase)
                .Add(ProviderStructuredReleaseBundle.NormalizeFingerprint(SignerFingerprint)),
            ProviderStartupTimeout = TimeSpan.FromSeconds(2),
            ProviderShutdownTimeout = TimeSpan.FromSeconds(1),
            EnableNetworkAccess = false,
            TransportLimits = OopTransportLimits.Default
        };

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

    private sealed class Wave5TempEntrypointArtifact : IDisposable
    {
        private Wave5TempEntrypointArtifact(string directoryPath, string entrypointPath)
        {
            DirectoryPath = directoryPath;
            EntrypointPath = entrypointPath;
        }

        public string DirectoryPath { get; }
        public string EntrypointPath { get; }

        public static Wave5TempEntrypointArtifact Create()
        {
            string directoryPath = Path.Combine(Path.GetTempPath(), "cybersuite-wave5-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directoryPath);

            string entrypointPath = Path.Combine(directoryPath, "provider-worker.dll");
            File.WriteAllBytes(entrypointPath, new byte[] { 0x43, 0x53, 0x57, 0x35, 0x01, 0x02, 0x03, 0x04 });

            return new Wave5TempEntrypointArtifact(directoryPath, entrypointPath);
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
            }
        }
    }

    private sealed class Wave5SinglePackageDiscovery : IProviderDiscovery
    {
        private readonly ProviderPackage _package;

        public Wave5SinglePackageDiscovery(ProviderPackage package)
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

    private sealed class Wave5StaticLauncher : IProviderLauncher
    {
        private readonly IProviderConnection _connection;

        public Wave5StaticLauncher(IProviderConnection connection)
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

    private sealed class Wave5TrackingLauncher : IProviderLauncher
    {
        private readonly IProviderConnection _connection;

        public Wave5TrackingLauncher(IProviderConnection connection)
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

    private sealed class Wave5FakeProductionConnection : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly CapabilitySnapshot _snapshot;
        private readonly ProviderComplianceEnvelope _envelope;
        private readonly byte[] _capabilityCanonicalBytes;
        private readonly byte[]? _attestationEvidence;
        private bool _disposed;

        public Wave5FakeProductionConnection(ProviderPackage package, bool includeAttestation)
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
