using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Threading;
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

public sealed class ProviderHostWave2Tests
{
    [Fact]
    public async Task StartAsync_LaunchTimeout_JournalsFailure_AndDoesNotRegisterProvider()
    {
        ProviderPackage package = CreatePackage(new ProviderId("TimeoutProvider"));
        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromMilliseconds(50)),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new HangingLauncher(),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Dev,
            RequiredBoundaryClass.None,
            experimentalAllowed: true,
            fipsRequired: false);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.Equal(ProviderHostLifecycleState.Started, host.LifecycleState);
        Assert.Empty(host.Snapshot.Providers);
        Assert.True(host.FailureJournal.HasFailures);
        Assert.Contains(
            host.FailureJournal.Entries,
            entry => entry.ReasonCode == ProviderHostReasonCodes.LaunchDeadlineExceeded && entry.State == ProviderLifecycleState.Faulted);
    }

    [Fact]
    public async Task StartAsync_DiscoveryFailure_RollsBackPendingProvider_AndAllowsRetry()
    {
        ProviderPackage package = CreatePackage(new ProviderId("RollbackProvider"));
        var discovery = new FailingThenHealthyDiscovery(package);
        var launcher = new FactoryLauncher(() => CreateReadyConnection(package));

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2)),
            discovery: discovery,
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: launcher,
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Dev,
            RequiredBoundaryClass.None,
            experimentalAllowed: true,
            fipsRequired: false);

        await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(binding, CancellationToken.None));

        Assert.Equal(ProviderHostLifecycleState.Stopped, host.LifecycleState);
        Assert.Empty(host.Snapshot.Providers);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.Equal(ProviderHostLifecycleState.Started, host.LifecycleState);
        Assert.True(host.Snapshot.Providers.ContainsKey(package.Manifest.ProviderId));
    }

    [Fact]
    public async Task StartAsync_ProdProfile_RejectsReferenceInProcessProvider_BeforeLaunch()
    {
        ProviderPackage package = CreatePackage(new ProviderId("ReferenceProvider"));
        var launcher = new TrackingLauncher(CreateReadyConnection(package));

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Prod, startupTimeout: TimeSpan.FromSeconds(2)),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: launcher,
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Prod,
            RequiredBoundaryClass.IsolatedProcess,
            experimentalAllowed: false,
            fipsRequired: false);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.False(launcher.LaunchInvoked);
        Assert.Empty(host.Snapshot.Providers);
        Assert.Contains(
            host.FailureJournal.Entries,
            entry => entry.ReasonCode == ProviderHostReasonCodes.BoundaryRequirementRejected
                  || entry.ReasonCode == ProviderHostReasonCodes.ReferenceProviderRejectedOutsideDev);
    }


    [Fact]
    public async Task StartAsync_ProfileMismatchBetweenBindingAndHost_Throws_AndLeavesHostStopped()
    {
        ProviderPackage package = CreatePackage(new ProviderId("ProfileMismatchProvider"));
        var launcher = new TrackingLauncher(CreateReadyConnection(package));

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Prod, startupTimeout: TimeSpan.FromSeconds(2)),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: launcher,
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Dev,
            RequiredBoundaryClass.None,
            experimentalAllowed: true,
            fipsRequired: false);

        await Assert.ThrowsAsync<InvalidOperationException>(() => host.StartAsync(binding, CancellationToken.None));

        Assert.False(launcher.LaunchInvoked);
        Assert.Equal(ProviderHostLifecycleState.Stopped, host.LifecycleState);
        Assert.Empty(host.Snapshot.Providers);
    }

    [Fact]
    public async Task OpenSession_ConcurrentKemCalls_AreSerializedPerProviderState()
    {
        ProviderPackage package = CreatePackage(new ProviderId("ConcurrentProvider"));
        var connection = CreateConcurrentKemConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2)),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Dev,
            RequiredBoundaryClass.None,
            experimentalAllowed: true,
            fipsRequired: false);

        await host.StartAsync(binding, CancellationToken.None);
        byte[] boundPolicyHash = binding.PolicyHashSha384.ToArray();

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            new ProviderSessionOptions(
                BoundPolicyHash: boundPolicyHash,
                FipsRequired: false,
                TenantId: null,
                EffectiveCompliance: binding.EffectiveCompliance),
            new DualComplianceGate());

        IKemService kem = session.GetKem(TestFixtures.Classical_KEM(package.Manifest.ProviderId).Id);

        Task[] tasks = Enumerable.Range(0, 8)
            .Select(_ => Task.Run(() => kem.GenerateKeyPair()))
            .ToArray();

        await Task.WhenAll(tasks);

        Assert.Equal(1, connection.MaxConcurrentKemGenerate);
    }


    [Fact]
    public async Task StopAsync_CancellationAfterEntry_DoesNotAbortCleanup()
    {
        ProviderPackage package = CreatePackage(new ProviderId("StopCleanupProvider"));
        var connection = CreateCoordinatedShutdownConnection(package, TimeSpan.FromMilliseconds(50));

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2)),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Dev,
            RequiredBoundaryClass.None,
            experimentalAllowed: true,
            fipsRequired: false);

        await host.StartAsync(binding, CancellationToken.None);

        using var cts = new CancellationTokenSource();
        Task stopTask = host.StopAsync(cts.Token);

        await connection.ShutdownStarted.Task;
        cts.Cancel();
        await stopTask;

        Assert.Equal(ProviderHostLifecycleState.Stopped, host.LifecycleState);
        Assert.Empty(host.Snapshot.Providers);
        Assert.True(connection.DisposeCalled);
    }

    [Fact]
    public async Task CompositeProviderLauncher_UsesRealLaunchContext_NotHardcodedDev()
    {
        ProviderPackage package = CreatePackage(new ProviderId("ContextProvider"));
        var handler = new RecordingHandler();
        var launcher = new CompositeProviderLauncher(handler);

        ProviderLaunchContext context = new(
            Profile: ExecutionProfile.Prod,
            TargetSecurityClass: ProviderSecurityClass.ProductionIsolated,
            RequiredBoundaryClass: RequiredBoundaryClass.IsolatedProcess,
            TransportBudget: OopTransportBudget.ForProfile(ExecutionProfile.Prod, OopTransportLimits.Default),
            EnableNetworkAccess: false,
            BoundPolicyHashSha384: ImmutableArray.CreateRange(new byte[48]),
            ExpectedProviderId: package.Manifest.ProviderId,
            ExpectedBuildHashSha256: null);

        await using IProviderConnection connection = await launcher.LaunchAsync(package, context, CancellationToken.None);

        Assert.NotNull(handler.ObservedContext);
        Assert.Equal(ExecutionProfile.Prod, handler.ObservedContext!.Profile);
        Assert.Equal(RequiredBoundaryClass.IsolatedProcess, handler.ObservedContext.RequiredBoundaryClass);
        Assert.Equal(ProviderSecurityClass.ProductionIsolated, handler.ObservedContext.TargetSecurityClass);
    }

    private static ProviderHostOptions CreateHostOptions(ExecutionProfile profile, TimeSpan startupTimeout)
        => new()
        {
            ExecutionProfile = profile,
            RequireNonEmptyAllowlistInProd = false,
            ProviderStartupTimeout = startupTimeout,
            ProviderShutdownTimeout = TimeSpan.FromSeconds(1),
            EnableNetworkAccess = false,
            TransportLimits = OopTransportLimits.Default
        };

    private static ProviderSessionBinding CreateBinding(
        ExecutionProfile profile,
        RequiredBoundaryClass requiredBoundaryClass,
        bool experimentalAllowed,
        bool fipsRequired)
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
            attestationRequirement: AttestationRequirement.None);

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

    private static ProviderPackage CreatePackage(ProviderId providerId)
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
                IsExperimental = false,
                FipsBoundaryDeclared = false,
                ComplianceEnvelope = ProviderComplianceEnvelope.ReferenceInProcessDefault,
                EntrypointSha256Hex = "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
            }
        };

    private static ProviderIdentity CreateIdentity(ProviderPackage package)
        => new(
            package.Manifest.ProviderId,
            package.Manifest.Version,
            package.Manifest.EntrypointSha256Hex ?? "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789",
            null);

    private static CapabilitySnapshot CreateSnapshot(ProviderPackage package)
        => CapabilitySnapshot.Create(
            CreateIdentity(package),
            ImmutableArray.Create(TestFixtures.Classical_KEM(package.Manifest.ProviderId)));

    private static StaticReadyConnection CreateReadyConnection(ProviderPackage package)
        => new(CreateIdentity(package), CreateSnapshot(package), package.Manifest.ComplianceEnvelope);

    private static ConcurrentKemConnection CreateConcurrentKemConnection(ProviderPackage package)
        => new(CreateIdentity(package), CreateSnapshot(package), package.Manifest.ComplianceEnvelope);


    private static CoordinatedShutdownConnection CreateCoordinatedShutdownConnection(ProviderPackage package, TimeSpan shutdownDelay)
        => new(CreateIdentity(package), CreateSnapshot(package), package.Manifest.ComplianceEnvelope, shutdownDelay);

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

    private sealed class FailingThenHealthyDiscovery : IProviderDiscovery
    {
        private readonly ProviderPackage _package;
        private int _attempts;

        public FailingThenHealthyDiscovery(ProviderPackage package)
        {
            _package = package;
        }

        public async IAsyncEnumerable<ProviderPackage> DiscoverAsync([EnumeratorCancellation] CancellationToken cancellationToken)
        {
            int attempt = Interlocked.Increment(ref _attempts);
            cancellationToken.ThrowIfCancellationRequested();
            yield return _package;

            if (attempt == 1)
                throw new InvalidOperationException("synthetic discovery failure");

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

    private sealed class FactoryLauncher : IProviderLauncher
    {
        private readonly Func<IProviderConnection> _factory;

        public FactoryLauncher(Func<IProviderConnection> factory)
        {
            _factory = factory;
        }

        public ValueTask<IProviderConnection> LaunchAsync(ProviderPackage package, ProviderLaunchContext launchContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            launchContext.Validate();
            return ValueTask.FromResult(_factory());
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

    private sealed class HangingLauncher : IProviderLauncher
    {
        public async ValueTask<IProviderConnection> LaunchAsync(ProviderPackage package, ProviderLaunchContext launchContext, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("The hanging launcher continuation should be unreachable.");
        }
    }

    private sealed class RecordingHandler : IProviderLaunchHandler
    {
        public ProviderLaunchContext? ObservedContext { get; private set; }

        public bool CanLaunch(ProviderPackage package, ProviderLaunchContext launchContext)
        {
            ObservedContext = launchContext;
            return launchContext.Profile == ExecutionProfile.Prod
                && launchContext.RequiredBoundaryClass == RequiredBoundaryClass.IsolatedProcess
                && launchContext.TargetSecurityClass == ProviderSecurityClass.ProductionIsolated;
        }

        public ValueTask<IProviderConnection> LaunchAsync(ProviderPackage package, ProviderLaunchContext launchContext, CancellationToken cancellationToken)
            => ValueTask.FromResult<IProviderConnection>(CreateReadyConnection(package));
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

    private class StaticReadyConnection : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly CapabilitySnapshot _snapshot;
        private readonly ProviderComplianceEnvelope _helloEnvelope;
        private readonly byte[] _capabilityCanonicalBytes;
        private bool _disposed;

        public StaticReadyConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope)
        {
            _identity = identity;
            _snapshot = snapshot;
            _helloEnvelope = helloEnvelope;
            _capabilityCanonicalBytes = snapshot.GetCanonicalBytes();
        }

        public virtual ValueTask<ProviderHello> HandshakeAsync(ClientHello clientHello, CancellationToken cancellationToken)
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
                    isExperimental: false,
                    attestationEvidence: null));
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

        public virtual ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
            => ValueTask.FromResult(new ShutdownResponse(SuccessHeader(request.Header, OopMessageType.ShutdownResponse)));

        public virtual ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var keyPair = new KemKeyPair(
                new PublicKey(request.AlgorithmId, new byte[97]),
                new PrivateKeyHandle(_identity.ProviderId, Guid.NewGuid()));

            return ValueTask.FromResult(new KemGenerateKeyPairResponse(SuccessHeader(request.Header, OopMessageType.KemGenerateKeyPairResponse), keyPair));
        }

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

        public virtual ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
        }

        protected void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }

        protected static OopResponseHeader SuccessHeader(OopRequestHeader header, OopMessageType responseType)
            => new(
                version: header.Version,
                messageType: responseType,
                requestId: header.RequestId,
                messageCounter: header.MessageCounter,
                channelBindingSha384: header.ChannelBindingSha384.Span,
                success: true,
                error: null);
    }

    private sealed class CoordinatedShutdownConnection : StaticReadyConnection
    {
        private readonly TimeSpan _shutdownDelay;

        public CoordinatedShutdownConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope,
            TimeSpan shutdownDelay)
            : base(identity, snapshot, helloEnvelope)
        {
            _shutdownDelay = shutdownDelay;
        }

        public TaskCompletionSource<bool> ShutdownStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool DisposeCalled { get; private set; }

        public override async ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
        {
            ShutdownStarted.TrySetResult(true);
            await Task.Delay(_shutdownDelay, CancellationToken.None).ConfigureAwait(false);
            return await base.ShutdownAsync(request, cancellationToken).ConfigureAwait(false);
        }

        public override ValueTask DisposeAsync()
        {
            DisposeCalled = true;
            return base.DisposeAsync();
        }
    }

    private sealed class ConcurrentKemConnection : StaticReadyConnection
    {
        private int _activeKemGenerate;
        private int _maxConcurrentKemGenerate;

        public ConcurrentKemConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope)
            : base(identity, snapshot, helloEnvelope)
        {
        }

        public int MaxConcurrentKemGenerate => Volatile.Read(ref _maxConcurrentKemGenerate);

        public override ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
        {
            int current = Interlocked.Increment(ref _activeKemGenerate);
            UpdateMaxConcurrent(current);

            try
            {
                Thread.Sleep(15);
                return base.KemGenerateKeyPairAsync(request, cancellationToken);
            }
            finally
            {
                Interlocked.Decrement(ref _activeKemGenerate);
            }
        }

        private void UpdateMaxConcurrent(int value)
        {
            while (true)
            {
                int observed = Volatile.Read(ref _maxConcurrentKemGenerate);
                if (value <= observed)
                    return;

                if (Interlocked.CompareExchange(ref _maxConcurrentKemGenerate, value, observed) == observed)
                    return;
            }
        }
    }
}
