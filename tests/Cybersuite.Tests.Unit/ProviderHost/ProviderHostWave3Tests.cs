using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
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

public sealed class ProviderHostWave3Tests
{
    [Fact]
    public async Task StartAsync_OversizedCapabilitySnapshot_RollsBackWithCapabilityBudgetExceeded()
    {
        ProviderPackage package = CreatePackage(new ProviderId("OversizedCapabilityProvider"));
        ProviderIdentity identity = CreateIdentity(package);

        byte[] oversizedCapabilityBytes = new byte[4096];
        RandomNumberGenerator.Fill(oversizedCapabilityBytes);
        byte[] capabilityHash = SHA384.HashData(oversizedCapabilityBytes);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2), maxMessageBytes: 1024),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(new OversizedCapabilityConnection(identity, package.Manifest.ComplianceEnvelope, oversizedCapabilityBytes, capabilityHash)),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding(
            ExecutionProfile.Dev,
            RequiredBoundaryClass.None,
            experimentalAllowed: true,
            fipsRequired: false);

        await host.StartAsync(binding, CancellationToken.None);

        Assert.Equal(ProviderHostLifecycleState.Started, host.LifecycleState);
        Assert.Empty(host.Snapshot.Providers);
        Assert.Contains(
            host.FailureJournal.Entries,
            entry => entry.ReasonCode == ProviderHostReasonCodes.CapabilityBudgetExceeded
                  && entry.State == ProviderLifecycleState.RolledBack);
    }

    [Fact]
    public async Task OpenSession_SignWithMismatchedPrivateKeyHandle_FailsClosed_BeforeRpc()
    {
        ProviderPackage package = CreatePackage(new ProviderId("SignatureMismatchProvider"));
        var connection = CreateSignatureConnection(package, signatureResponseBytes: 96);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2), maxMessageBytes: 1024),
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

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            new ProviderSessionOptions(
                BoundPolicyHash: binding.PolicyHashSha384.ToArray(),
                FipsRequired: false,
                TenantId: null,
                EffectiveCompliance: binding.EffectiveCompliance),
            new DualComplianceGate());

        ISignatureService signature = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        PrivateKeyHandle mismatchedHandle = new(new ProviderId("OtherProvider"), Guid.NewGuid());
        byte[] message = new byte[32];
        byte[] signatureOut = new byte[96];

        var ex = Assert.Throws<InvalidOperationException>(() => signature.Sign(mismatchedHandle, message, signatureOut));

        Assert.Contains("provider mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, connection.SignatureSignCallCount);
    }

    [Fact]
    public async Task OpenSession_OversizedSignatureRequest_ThrowsBudgetExceeded_BeforeRpc()
    {
        ProviderPackage package = CreatePackage(new ProviderId("SignatureBudgetRequestProvider"));
        var connection = CreateSignatureConnection(package, signatureResponseBytes: 96);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2), maxMessageBytes: 1024),
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

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            new ProviderSessionOptions(
                BoundPolicyHash: binding.PolicyHashSha384.ToArray(),
                FipsRequired: false,
                TenantId: null,
                EffectiveCompliance: binding.EffectiveCompliance),
            new DualComplianceGate());

        ISignatureService signature = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = signature.GenerateKeyPair();
        byte[] oversizedMessage = new byte[2048];
        byte[] signatureOut = new byte[96];

        var ex = Assert.Throws<OopTransportBudgetExceededException>(() =>
            signature.Sign(keyPair.PrivateKey, oversizedMessage, signatureOut));

        Assert.Contains("Signature sign", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, connection.SignatureSignCallCount);
    }

    [Fact]
    public async Task OpenSession_OversizedSignatureResponse_ThrowsBudgetExceeded_AfterRpc()
    {
        ProviderPackage package = CreatePackage(new ProviderId("SignatureBudgetResponseProvider"));
        var connection = CreateSignatureConnection(package, signatureResponseBytes: 2048);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(ExecutionProfile.Dev, startupTimeout: TimeSpan.FromSeconds(2), maxMessageBytes: 1024),
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

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            new ProviderSessionOptions(
                BoundPolicyHash: binding.PolicyHashSha384.ToArray(),
                FipsRequired: false,
                TenantId: null,
                EffectiveCompliance: binding.EffectiveCompliance),
            new DualComplianceGate());

        ISignatureService signature = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = signature.GenerateKeyPair();
        byte[] message = new byte[16];
        byte[] signatureOut = new byte[2048];

        var ex = Assert.Throws<OopTransportBudgetExceededException>(() =>
            signature.Sign(keyPair.PrivateKey, message, signatureOut));

        Assert.Contains("response", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(1, connection.SignatureSignCallCount);
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

    private static TrackingSignatureConnection CreateSignatureConnection(ProviderPackage package, int signatureResponseBytes)
    {
        ProviderIdentity identity = CreateIdentity(package);
        CapabilitySnapshot snapshot = CapabilitySnapshot.Create(
            identity,
            ImmutableArray.Create(TestFixtures.Classical_Sig(package.Manifest.ProviderId)));

        return new TrackingSignatureConnection(identity, snapshot, package.Manifest.ComplianceEnvelope, signatureResponseBytes);
    }

    private static ProviderHostOptions CreateHostOptions(
        ExecutionProfile profile,
        TimeSpan startupTimeout,
        int maxMessageBytes)
        => new()
        {
            ExecutionProfile = profile,
            RequireNonEmptyAllowlistInProd = false,
            ProviderIdAllowlist = ImmutableHashSet<ProviderId>.Empty,
            ExpectedEntrypointSha256ByProvider = ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
            ProviderStartupTimeout = startupTimeout,
            ProviderShutdownTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkAccess = false,
            TransportLimits = new OopTransportLimits
            {
                MaxReceiveMessageSizeBytes = maxMessageBytes,
                MaxSendMessageSizeBytes = maxMessageBytes
            }
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
            ExecutionProfile = effective.Profile,
            FipsRequired = effective.EffectiveFipsRequired,
            ExperimentalAllowed = effective.ExperimentalAllowed,
            TenantId = effective.TenantId,
            ExpectedProviderId = null,
            ExpectedBuildHash = null,
            EffectiveCompliance = effective
        };
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

    private abstract class TestConnectionBase : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly ProviderComplianceEnvelope _helloEnvelope;
        private readonly byte[] _capabilityCanonicalBytes;
        private readonly byte[] _capabilityHashSha384;
        private bool _disposed;

        protected TestConnectionBase(
            ProviderIdentity identity,
            ProviderComplianceEnvelope helloEnvelope,
            ReadOnlySpan<byte> capabilityCanonicalBytes,
            ReadOnlySpan<byte> capabilityHashSha384)
        {
            _identity = identity;
            _helloEnvelope = helloEnvelope;
            _capabilityCanonicalBytes = capabilityCanonicalBytes.ToArray();
            _capabilityHashSha384 = capabilityHashSha384.ToArray();
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
                    capabilityHashSha384: _capabilityHashSha384,
                    complianceEnvelope: _helloEnvelope,
                    isExperimental: false,
                    attestationEvidence: null));
        }

        public virtual ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return ValueTask.FromResult(
                new CapabilityResponse(
                    header: SuccessHeader(request.Header, OopMessageType.CapabilityResponse),
                    capabilityCanonicalBytes: _capabilityCanonicalBytes,
                    capabilityHashSha384: _capabilityHashSha384));
        }

        public ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            return ValueTask.FromResult(new ShutdownResponse(SuccessHeader(request.Header, OopMessageType.ShutdownResponse)));
        }

        public virtual ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<KemEncapsulateResponse> KemEncapsulateAsync(KemEncapsulateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<KemDecapsulateResponse> KemDecapsulateAsync(KemDecapsulateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<SignatureVerifyResponse> SignatureVerifyAsync(SignatureVerifyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<AeadGenerateKeyResponse> AeadGenerateKeyAsync(AeadGenerateKeyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<AeadEncryptResponse> AeadEncryptAsync(AeadEncryptRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<AeadDecryptResponse> AeadDecryptAsync(AeadDecryptRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<KdfDeriveKeyResponse> KdfDeriveKeyAsync(KdfDeriveKeyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public virtual ValueTask<DestroyHandleResponse> DestroyHandleAsync(DestroyHandleRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask DisposeAsync()
        {
            _disposed = true;
            return ValueTask.CompletedTask;
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

        protected void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }
    }

    private sealed class OversizedCapabilityConnection : TestConnectionBase
    {
        public OversizedCapabilityConnection(
            ProviderIdentity identity,
            ProviderComplianceEnvelope helloEnvelope,
            ReadOnlySpan<byte> capabilityCanonicalBytes,
            ReadOnlySpan<byte> capabilityHashSha384)
            : base(identity, helloEnvelope, capabilityCanonicalBytes, capabilityHashSha384)
        {
        }
    }

    private sealed class TrackingSignatureConnection : TestConnectionBase
    {
        private readonly ProviderId _providerId;
        private readonly int _signatureResponseBytes;

        public TrackingSignatureConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope,
            int signatureResponseBytes)
            : base(identity, helloEnvelope, snapshot.GetCanonicalBytes(), snapshot.CapabilityHashSha384.Span)
        {
            _providerId = identity.ProviderId;
            _signatureResponseBytes = signatureResponseBytes;
        }

        public int SignatureSignCallCount { get; private set; }

        public override ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            SignatureSignCallCount++;
            return ValueTask.FromResult(
                new SignatureSignResponse(
                    SuccessHeader(request.Header, OopMessageType.SignatureSignResponse),
                    new byte[_signatureResponseBytes]));
        }

        public override ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var publicKey = new PublicKey(request.AlgorithmId, new byte[97]);
            var privateKey = new PrivateKeyHandle(_providerId, Guid.NewGuid());
            return ValueTask.FromResult(
                new SignatureGenerateKeyPairResponse(
                    SuccessHeader(request.Header, OopMessageType.SignatureGenerateKeyPairResponse),
                    new SignatureKeyPair(publicKey, privateKey)));
        }
    }
}
