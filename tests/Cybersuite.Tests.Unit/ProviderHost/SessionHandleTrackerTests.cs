using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
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

/// <summary>
/// Comprehensive tests for F2/F3 session-binding enforcement:
/// - Session-scoped handle ownership validation (F2)
/// - Auto-cleanup on session dispose (F3)
/// - Cross-session handle rejection
/// - Track / untrack lifecycle
/// </summary>
public sealed class SessionHandleTrackerTests
{
    // ── F2: Cross-session handle rejection ────────────────────────

    [Fact]
    public async Task Sign_WithHandleFromDifferentSession_FailsClosed()
    {
        ProviderPackage package = CreatePackage(new ProviderId("CrossSessionSigProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session1 = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        using IProviderSession session2 = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        // Generate a key pair through session1
        ISignatureService sig1 = session1.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = sig1.GenerateKeyPair();

        // Attempt to use that handle in session2
        ISignatureService sig2 = session2.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        byte[] message = new byte[32];
        byte[] signatureOut = new byte[96];

        var ex = Assert.Throws<InvalidOperationException>(() =>
            sig2.Sign(keyPair.PrivateKey, message, signatureOut));

        Assert.Contains("not owned by this session", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Destroy_WithHandleFromDifferentSession_FailsClosed()
    {
        ProviderPackage package = CreatePackage(new ProviderId("CrossSessionDestroyProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session1 = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        using IProviderSession session2 = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        // Generate key pair through session1
        ISignatureService sig1 = session1.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = sig1.GenerateKeyPair();

        // Try to destroy the handle via session2
        var ex = Assert.Throws<InvalidOperationException>(() =>
            session2.Destroy(keyPair.PrivateKey));

        Assert.Contains("not owned by this session", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── F2: Fabricated handle rejection ────────────────────────────

    [Fact]
    public async Task Sign_WithFabricatedHandle_FailsClosed()
    {
        ProviderPackage package = CreatePackage(new ProviderId("FabricatedHandleProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        ISignatureService sig = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);

        // Fabricate a handle with the correct provider ID but never generated through a session
        PrivateKeyHandle fabricated = new(package.Manifest.ProviderId, Guid.NewGuid());
        byte[] message = new byte[32];
        byte[] signatureOut = new byte[96];

        var ex = Assert.Throws<InvalidOperationException>(() =>
            sig.Sign(fabricated, message, signatureOut));

        Assert.Contains("not owned by this session", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Destroy_WithFabricatedPrivateKeyHandle_FailsClosed()
    {
        ProviderPackage package = CreatePackage(new ProviderId("FabricatedDestroyProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        PrivateKeyHandle fabricated = new(package.Manifest.ProviderId, Guid.NewGuid());

        var ex = Assert.Throws<InvalidOperationException>(() =>
            session.Destroy(fabricated));

        Assert.Contains("not owned by this session", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── F2: Tracked handle succeeds ──────────────────────────────

    [Fact]
    public async Task Sign_WithTrackedHandle_Succeeds()
    {
        ProviderPackage package = CreatePackage(new ProviderId("TrackedSignProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        ISignatureService sig = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = sig.GenerateKeyPair();

        byte[] message = new byte[32];
        byte[] signatureOut = new byte[96];

        // Should succeed because the handle is tracked by this session
        sig.Sign(keyPair.PrivateKey, message, signatureOut);
        Assert.Equal(1, connection.SignatureSignCallCount);
    }

    [Fact]
    public async Task Destroy_WithTrackedHandle_Succeeds()
    {
        ProviderPackage package = CreatePackage(new ProviderId("TrackedDestroyProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        ISignatureService sig = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = sig.GenerateKeyPair();

        // Should succeed: handle was generated through this session
        session.Destroy(keyPair.PrivateKey);
        Assert.Equal(1, connection.DestroyCallCount);
    }

    // ── F2: Double-destroy rejection ─────────────────────────────

    [Fact]
    public async Task Destroy_SameHandleTwice_SecondCallFailsClosed()
    {
        ProviderPackage package = CreatePackage(new ProviderId("DoubleDestroyProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        ISignatureService sig = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = sig.GenerateKeyPair();

        session.Destroy(keyPair.PrivateKey);

        // Second destroy should fail because the handle was untracked
        var ex = Assert.Throws<InvalidOperationException>(() =>
            session.Destroy(keyPair.PrivateKey));

        Assert.Contains("not owned by this session", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── F3: Auto-cleanup on session dispose ──────────────────────

    [Fact]
    public async Task Dispose_Session_DestroysRemainingHandles_BestEffort()
    {
        ProviderPackage package = CreatePackage(new ProviderId("AutoCleanupProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        // Generate 3 key pairs, explicitly destroy only 1
        ISignatureService sig = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair kp1 = sig.GenerateKeyPair();
        SignatureKeyPair kp2 = sig.GenerateKeyPair();
        SignatureKeyPair kp3 = sig.GenerateKeyPair();
        session.Destroy(kp1.PrivateKey);

        int destroyCountBeforeDispose = connection.DestroyCallCount;
        Assert.Equal(1, destroyCountBeforeDispose);

        // Dispose should auto-destroy the remaining 2 handles
        session.Dispose();
        Assert.Equal(3, connection.DestroyCallCount);
    }

    [Fact]
    public async Task Dispose_Session_TrackedHandlesAreInvalidated_CannotBeUsedAfterward()
    {
        ProviderPackage package = CreatePackage(new ProviderId("PostDisposeRejectProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        ISignatureService sig = session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id);
        SignatureKeyPair keyPair = sig.GenerateKeyPair();

        session.Dispose();

        // Session is disposed — any subsequent operation should fail
        Assert.Throws<ObjectDisposedException>(() =>
            session.GetSignature(TestFixtures.Classical_Sig(package.Manifest.ProviderId).Id));
    }

    // ── F2: AEAD handle tracking ─────────────────────────────────

    [Fact]
    public async Task AeadEncrypt_WithFabricatedSecretKeyHandle_FailsClosed()
    {
        ProviderPackage package = CreatePackage(new ProviderId("AeadFabricatedProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        IAeadService aead = session.GetAead(TestFixtures.Aes256Gcm);
        SecretKeyHandle fabricated = new(package.Manifest.ProviderId, Guid.NewGuid());

        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ad = Array.Empty<byte>();
        byte[] ciphertextOut = new byte[32 + 16];

        var ex = Assert.Throws<InvalidOperationException>(() =>
            aead.Encrypt(fabricated, nonce, plaintext, ad, ciphertextOut));

        Assert.Contains("not owned by this session", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AeadEncrypt_WithTrackedSecretKeyHandle_Succeeds()
    {
        ProviderPackage package = CreatePackage(new ProviderId("AeadTrackedProvider"));
        var connection = CreateFullConnection(package);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using IProviderSession session = host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        IAeadService aead = session.GetAead(TestFixtures.Aes256Gcm);
        SecretKeyHandle key = aead.GenerateKey();

        byte[] nonce = new byte[12];
        byte[] plaintext = new byte[32];
        byte[] ad = Array.Empty<byte>();
        byte[] ciphertextOut = new byte[32 + 16];

        aead.Encrypt(key, nonce, plaintext, ad, ciphertextOut);
        Assert.Equal(1, connection.AeadEncryptCallCount);
    }

    // ── Infrastructure ───────────────────────────────────────────

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

    private static FullTrackingConnection CreateFullConnection(ProviderPackage package)
    {
        ProviderIdentity identity = CreateIdentity(package);
        CapabilitySnapshot snapshot = CapabilitySnapshot.Create(
            identity,
            ImmutableArray.Create(
                TestFixtures.Classical_Sig(package.Manifest.ProviderId),
                TestFixtures.Aead(package.Manifest.ProviderId)));

        return new FullTrackingConnection(identity, snapshot, package.Manifest.ComplianceEnvelope);
    }

    private static ProviderHostOptions CreateHostOptions()
        => new()
        {
            ExecutionProfile = ExecutionProfile.Dev,
            RequireNonEmptyAllowlistInProd = false,
            ProviderIdAllowlist = ImmutableHashSet<ProviderId>.Empty,
            ExpectedEntrypointSha256ByProvider = ImmutableDictionary<ProviderId, ImmutableArray<byte>>.Empty,
            ProviderStartupTimeout = TimeSpan.FromSeconds(2),
            ProviderShutdownTimeout = TimeSpan.FromSeconds(2),
            EnableNetworkAccess = false,
            TransportLimits = new OopTransportLimits
            {
                MaxReceiveMessageSizeBytes = 8192,
                MaxSendMessageSizeBytes = 8192
            }
        };

    private static ProviderSessionBinding CreateBinding()
    {
        EffectiveComplianceContext effective = new(
            profile: ExecutionProfile.Dev,
            policyHashSha384: new byte[48],
            tenantId: null,
            policyFipsRequired: false,
            forceFips: null,
            experimentalAllowed: true,
            requiredBoundaryClass: RequiredBoundaryClass.None,
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

    private static ProviderSessionOptions CreateSessionOptions(ProviderSessionBinding binding)
        => new(
            BoundPolicyHash: binding.PolicyHashSha384.ToArray(),
            FipsRequired: false,
            TenantId: null,
            EffectiveCompliance: binding.EffectiveCompliance);

    private sealed class SinglePackageDiscovery : IProviderDiscovery
    {
        private readonly ProviderPackage _package;

        public SinglePackageDiscovery(ProviderPackage package) => _package = package;

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

        public StaticLauncher(IProviderConnection connection) => _connection = connection;

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

    /// <summary>
    /// Full-featured mock connection supporting Signature, AEAD, and Destroy operations
    /// with call tracking for test assertions.
    /// </summary>
    private sealed class FullTrackingConnection : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly ProviderComplianceEnvelope _helloEnvelope;
        private readonly byte[] _capabilityCanonicalBytes;
        private readonly byte[] _capabilityHashSha384;
        private bool _disposed;

        public FullTrackingConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope)
        {
            _identity = identity;
            _helloEnvelope = helloEnvelope;
            _capabilityCanonicalBytes = snapshot.GetCanonicalBytes();
            _capabilityHashSha384 = snapshot.CapabilityHashSha384.Span.ToArray();
        }

        public int SignatureSignCallCount { get; private set; }
        public int DestroyCallCount { get; private set; }
        public int AeadEncryptCallCount { get; private set; }

        public ValueTask<ProviderHello> HandshakeAsync(ClientHello clientHello, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
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

        public ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                new CapabilityResponse(
                    header: SuccessHeader(request.Header, OopMessageType.CapabilityResponse),
                    capabilityCanonicalBytes: _capabilityCanonicalBytes,
                    capabilityHashSha384: _capabilityHashSha384));
        }

        public ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new ShutdownResponse(SuccessHeader(request.Header, OopMessageType.ShutdownResponse)));
        }

        public ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<KemEncapsulateResponse> KemEncapsulateAsync(KemEncapsulateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<KemDecapsulateResponse> KemDecapsulateAsync(KemDecapsulateRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var publicKey = new PublicKey(request.AlgorithmId, new byte[97]);
            var privateKey = new PrivateKeyHandle(_identity.ProviderId, Guid.NewGuid());
            return ValueTask.FromResult(
                new SignatureGenerateKeyPairResponse(
                    SuccessHeader(request.Header, OopMessageType.SignatureGenerateKeyPairResponse),
                    new SignatureKeyPair(publicKey, privateKey)));
        }

        public ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SignatureSignCallCount++;
            return ValueTask.FromResult(
                new SignatureSignResponse(
                    SuccessHeader(request.Header, OopMessageType.SignatureSignResponse),
                    new byte[96]));
        }

        public ValueTask<SignatureVerifyResponse> SignatureVerifyAsync(SignatureVerifyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<AeadGenerateKeyResponse> AeadGenerateKeyAsync(AeadGenerateKeyRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var keyHandle = new SecretKeyHandle(_identity.ProviderId, Guid.NewGuid());
            return ValueTask.FromResult(
                new AeadGenerateKeyResponse(
                    SuccessHeader(request.Header, OopMessageType.AeadGenerateKeyResponse),
                    keyHandle));
        }

        public ValueTask<AeadEncryptResponse> AeadEncryptAsync(AeadEncryptRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            AeadEncryptCallCount++;
            byte[] ciphertext = new byte[request.Plaintext.Length + 16]; // plaintext + tag
            return ValueTask.FromResult(
                new AeadEncryptResponse(
                    SuccessHeader(request.Header, OopMessageType.AeadEncryptResponse),
                    ciphertext));
        }

        public ValueTask<AeadDecryptResponse> AeadDecryptAsync(AeadDecryptRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<KdfDeriveKeyResponse> KdfDeriveKeyAsync(KdfDeriveKeyRequest request, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<DestroyHandleResponse> DestroyHandleAsync(DestroyHandleRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DestroyCallCount++;
            return ValueTask.FromResult(
                new DestroyHandleResponse(SuccessHeader(request.Header, OopMessageType.DestroyHandleResponse)));
        }

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
    }
}
