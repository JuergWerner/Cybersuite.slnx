using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Cybersuite.Abstractions;
using Cybersuite.Compliance;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Discovery;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;
using Xunit;

using ProviderHostRuntime = Cybersuite.ProviderHost.ProviderHost;

namespace Cybersuite.Tests.Unit.ProviderHost;

public sealed class ProviderHostWave1Tests
{
    [Fact]
    public async Task StartAsync_ManifestHelloEnvelopeMismatch_DoesNotRegisterProvider()
    {
        ProviderPackage package = CreatePackage(
            providerId: new ProviderId("MismatchProvider"),
            complianceEnvelope: ProviderComplianceEnvelope.ReferenceInProcessDefault,
            isExperimental: false);

        ProviderIdentity identity = CreateIdentity(package);
        CapabilitySnapshot snapshot = CapabilitySnapshot.Create(
            identity,
            ImmutableArray.Create(TestFixtures.Aead(package.Manifest.ProviderId)));

        ProviderComplianceEnvelope mismatchedEnvelope = new(
            securityClass: ProviderSecurityClass.ValidatedBoundary,
            boundaryClass: RequiredBoundaryClass.ValidatedBoundary,
            declaredValidatedBoundary: true,
            declaredModuleName: "Module-X",
            declaredCertificateReference: "CERT-X",
            declaredModuleVersion: "1.0.0",
            supportsNonExportableKeys: true,
            supportsRawSecretEgress: false,
            attestationMode: AttestationMode.None);

        await using ProviderHostRuntime host = CreateHost(
            package,
            new StaticTestProviderConnection(identity, snapshot, mismatchedEnvelope, isExperimental: false));

        ProviderSessionBinding binding = CreateBinding(
            CreateEffectiveCompliance(
                profile: ExecutionProfile.Dev,
                policyFipsRequired: false,
                forceFips: null,
                requiredBoundaryClass: RequiredBoundaryClass.None));

        await host.StartAsync(binding, CancellationToken.None);

        Assert.Equal(ProviderHostLifecycleState.Started, host.LifecycleState);
        Assert.Empty(host.Snapshot.Providers);
        Assert.True(host.FailureJournal.HasFailures);
    }

    [Fact]
    public async Task StartAsync_EffectiveValidatedBoundary_RejectsReferenceProvider()
    {
        ProviderPackage package = CreatePackage(
            providerId: new ProviderId("ReferenceProvider"),
            complianceEnvelope: ProviderComplianceEnvelope.ReferenceInProcessDefault,
            isExperimental: false);

        ProviderIdentity identity = CreateIdentity(package);
        CapabilitySnapshot snapshot = CapabilitySnapshot.Create(
            identity,
            ImmutableArray.Create(TestFixtures.Fips_KEM(package.Manifest.ProviderId)));

        await using ProviderHostRuntime host = CreateHost(
            package,
            new StaticTestProviderConnection(identity, snapshot, package.Manifest.ComplianceEnvelope, isExperimental: false),
            executionProfile: ExecutionProfile.Prod);

        EffectiveComplianceContext effective = CreateEffectiveCompliance(
            profile: ExecutionProfile.Prod,
            policyFipsRequired: true,
            forceFips: null,
            requiredBoundaryClass: RequiredBoundaryClass.ValidatedBoundary);

        ProviderSessionBinding binding = CreateBinding(effective);
        await host.StartAsync(binding, CancellationToken.None);

        Assert.Empty(host.Snapshot.Providers);
    }

    private static ProviderHostRuntime CreateHost(
        ProviderPackage package,
        IProviderConnection connection,
        ExecutionProfile executionProfile = ExecutionProfile.Dev)
        => new(
            options: new ProviderHostOptions
            {
                ExecutionProfile = executionProfile,
                RequireNonEmptyAllowlistInProd = false,
                ProviderIdAllowlist = ImmutableHashSet<ProviderId>.Empty,
                ExpectedEntrypointSha256ByProvider = ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
                ProviderStartupTimeout = TimeSpan.FromSeconds(5),
                ProviderShutdownTimeout = TimeSpan.FromSeconds(2),
                EnableNetworkAccess = false,
                TransportLimits = OopTransportLimits.Default
            },
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticProviderLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

    private static ProviderSessionBinding CreateBinding(EffectiveComplianceContext effective)
        => new()
        {
            PolicyHashSha384 = effective.PolicyHashSha384,
            ExecutionProfile = effective.Profile,
            FipsRequired = effective.EffectiveFipsRequired,
            ExperimentalAllowed = effective.ExperimentalAllowed,
            TenantId = effective.TenantId,
            ExpectedProviderId = null,
            ExpectedBuildHash = null,
            EffectiveCompliance = effective
        };

    private static EffectiveComplianceContext CreateEffectiveCompliance(
        ExecutionProfile profile,
        bool policyFipsRequired,
        bool? forceFips,
        RequiredBoundaryClass requiredBoundaryClass)
        => new(
            profile: profile,
            policyHashSha384: new byte[48],
            tenantId: null,
            policyFipsRequired: policyFipsRequired,
            forceFips: forceFips,
            experimentalAllowed: true,
            requiredBoundaryClass: requiredBoundaryClass,
            requiredProviderIds: ImmutableHashSet<ProviderId>.Empty,
            requiredBuildHashes: ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
            attestationRequirement: AttestationRequirement.None);

    private static ProviderPackage CreatePackage(
        ProviderId providerId,
        ProviderComplianceEnvelope complianceEnvelope,
        bool isExperimental)
        => new()
        {
            PackageRoot = "/virtual/package",
            EntrypointPath = "/virtual/package/provider.dll",
            Manifest = new ProviderManifest
            {
                ProviderId = providerId,
                Version = "1.0.0",
                Vendor = "TestVendor",
                IsolationMode = ProviderIsolationMode.InProcess,
                IsExperimental = isExperimental,
                FipsBoundaryDeclared = complianceEnvelope.DeclaredValidatedBoundary,
                ComplianceEnvelope = complianceEnvelope,
                EntrypointSha256Hex = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
                SignatureBundleBase64 = null
            }
        };

    private static ProviderIdentity CreateIdentity(ProviderPackage package)
        => new(
            package.Manifest.ProviderId,
            package.Manifest.Version,
            package.Manifest.EntrypointSha256Hex ?? "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            null);

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

    private sealed class StaticProviderLauncher : IProviderLauncher
    {
        private readonly IProviderConnection _connection;

        public StaticProviderLauncher(IProviderConnection connection)
        {
            _connection = connection;
        }

        public ValueTask<IProviderConnection> LaunchAsync(
            ProviderPackage package,
            ProviderLaunchContext launchContext,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            launchContext.Validate();
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

    private sealed class StaticTestProviderConnection : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly CapabilitySnapshot _snapshot;
        private readonly byte[] _capabilityCanonicalBytes;
        private readonly ProviderComplianceEnvelope _helloEnvelope;
        private readonly bool _isExperimental;
        private bool _disposed;

        public StaticTestProviderConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope,
            bool isExperimental)
        {
            _identity = identity;
            _snapshot = snapshot;
            _capabilityCanonicalBytes = snapshot.GetCanonicalBytes();
            _helloEnvelope = helloEnvelope;
            _isExperimental = isExperimental;
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
                    complianceEnvelope: _helloEnvelope,
                    isExperimental: _isExperimental,
                    attestationEvidence: null));
        }

        public ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return ValueTask.FromResult(
                new CapabilityResponse(
                    header: SuccessHeader(request.Header, OopMessageType.CapabilityResponse),
                    capabilityCanonicalBytes: _capabilityCanonicalBytes,
                    capabilityHashSha384: _snapshot.CapabilityHashSha384.Span));
        }

        public ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return ValueTask.FromResult(new ShutdownResponse(SuccessHeader(request.Header, OopMessageType.ShutdownResponse)));
        }

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
            => throw new NotSupportedException();

        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
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

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(StaticTestProviderConnection));
        }
    }
}
