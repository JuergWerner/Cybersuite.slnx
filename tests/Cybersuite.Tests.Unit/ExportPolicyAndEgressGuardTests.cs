using System;
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
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Discovery;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;
using Org.BouncyCastle.Crypto.Parameters;
using Xunit;

using ProviderHostRuntime = Cybersuite.ProviderHost.ProviderHost;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// Tests for F6 (KeyExportPolicy enforcement) and F7 (raw secret egress guard).
/// </summary>
public sealed class ExportPolicyAndEgressGuardTests
{
    private static readonly ProviderId TestProvider = new("BouncyCastle");
    private static readonly AlgorithmId EcdhP384 = new("ECDH-P384-KEM");

    // ── F6: KeyExportPolicy.AllowExplicit ────────────────────

    [Fact]
    public void ExportPrivateKey_AllowExplicit_Succeeds()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var handle = store.AddPrivateKey(TestProvider, (ECPrivateKeyParameters)kp.Private);

        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey, KeyExportPolicy.AllowExplicit);

        byte[] exported = svc.ExportPrivateKey(handle, options);
        try
        {
            Assert.InRange(exported.Length, 1, 48);
            Assert.True(exported.AsSpan().ContainsAnyExcept((byte)0), "Exported key should be non-zero.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(exported);
        }
    }

    // ── F6: KeyExportPolicy.DenyByDefault ────────────────────

    [Fact]
    public void ExportPrivateKey_DenyByDefault_ThrowsInvalidOperation()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var handle = store.AddPrivateKey(TestProvider, (ECPrivateKeyParameters)kp.Private);

        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey, KeyExportPolicy.DenyByDefault);

        var ex = Assert.Throws<InvalidOperationException>(() => svc.ExportPrivateKey(handle, options));
        Assert.Contains("denied by policy", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExportPrivateKeySecure_DenyByDefault_ThrowsInvalidOperation()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var handle = store.AddPrivateKey(TestProvider, (ECPrivateKeyParameters)kp.Private);

        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey, KeyExportPolicy.DenyByDefault);

        var ex = Assert.Throws<InvalidOperationException>(() => svc.ExportPrivateKeySecure(handle, options));
        Assert.Contains("denied by policy", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── F6: KeyExportPolicy.Prohibited ───────────────────────

    [Fact]
    public void ExportPrivateKey_Prohibited_ThrowsInvalidOperation()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var handle = store.AddPrivateKey(TestProvider, (ECPrivateKeyParameters)kp.Private);

        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey, KeyExportPolicy.Prohibited);

        var ex = Assert.Throws<InvalidOperationException>(() => svc.ExportPrivateKey(handle, options));
        Assert.Contains("prohibited", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ExportPrivateKeySecure_Prohibited_ThrowsInvalidOperation()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var handle = store.AddPrivateKey(TestProvider, (ECPrivateKeyParameters)kp.Private);

        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey, KeyExportPolicy.Prohibited);

        var ex = Assert.Throws<InvalidOperationException>(() => svc.ExportPrivateKeySecure(handle, options));
        Assert.Contains("prohibited", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── F6: PublicKey export is NOT gated by policy ──────────

    [Fact]
    public void ExportPublicKey_Prohibited_StillSucceeds()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        using var svc = new BouncyCastleKeyImportExportService(store, TestProvider);

        var kp = BouncyCastleCurveP384.GenerateKeyPair(new Org.BouncyCastle.Security.SecureRandom());
        var pubKey = BouncyCastleCurveP384.ToPublicKey(EcdhP384, (ECPublicKeyParameters)kp.Public);

        // Public key export should always succeed regardless of export policy
        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPublicKey, KeyExportPolicy.Prohibited);

        byte[] exported = svc.ExportPublicKey(pubKey, options);
        Assert.Equal(97, exported.Length);
    }

    // ── F6: DefaultPolicyForProfile mapping ──────────────────

    [Theory]
    [InlineData(ExecutionProfile.Dev, KeyExportPolicy.AllowExplicit)]
    [InlineData(ExecutionProfile.Staging, KeyExportPolicy.DenyByDefault)]
    [InlineData(ExecutionProfile.Prod, KeyExportPolicy.Prohibited)]
    public void DefaultPolicyForProfile_MapsCorrectly(ExecutionProfile profile, KeyExportPolicy expected)
    {
        Assert.Equal(expected, KeyExportOptions.DefaultPolicyForProfile(profile));
    }

    // ── F6: Default value backward compatibility ─────────────

    [Fact]
    public void KeyExportOptions_DefaultPolicy_IsAllowExplicit()
    {
        var options = new KeyExportOptions(EcdhP384, null, AlgorithmEncodingProfile.RawPrivateKey);
        Assert.Equal(KeyExportPolicy.AllowExplicit, options.ExportPolicy);
    }

    // ── F7: Raw secret egress guard ──────────────────────────

    [Fact]
    public async Task Session_RawSecretEgressDisabled_AssertThrowsOnExportAttempt()
    {
        // Create a provider with SupportsRawSecretEgress = false
        // Must use ReferenceInProcess + None boundary to match InProcess isolation mode.
        var noEgressEnvelope = new ProviderComplianceEnvelope(
            securityClass: ProviderSecurityClass.ReferenceInProcess,
            boundaryClass: RequiredBoundaryClass.None,
            declaredValidatedBoundary: false,
            declaredModuleName: null,
            declaredCertificateReference: null,
            declaredModuleVersion: null,
            supportsNonExportableKeys: true,
            supportsRawSecretEgress: false,
            attestationMode: AttestationMode.None);

        ProviderPackage package = CreatePackage(new ProviderId("NoEgressProvider"), noEgressEnvelope);
        var connection = CreateFullConnection(package, noEgressEnvelope);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using var session = (ProviderRpcSession)host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        var ex = Assert.Throws<InvalidOperationException>(() =>
            session.AssertRawSecretEgressPermitted("ExportPrivateKey"));

        Assert.Contains("Raw secret egress is not permitted", ex.Message);
        Assert.Contains("SupportsRawSecretEgress=false", ex.Message);
    }

    [Fact]
    public async Task Session_RawSecretEgressEnabled_AssertSucceeds()
    {
        // Standard in-process provider has SupportsRawSecretEgress = true
        ProviderPackage package = CreatePackage(new ProviderId("EgressAllowedProvider"),
            ProviderComplianceEnvelope.ReferenceInProcessDefault);
        var connection = CreateFullConnection(package, ProviderComplianceEnvelope.ReferenceInProcessDefault);

        await using var host = new ProviderHostRuntime(
            options: CreateHostOptions(),
            discovery: new SinglePackageDiscovery(package),
            trustEvaluator: AllowAllTrustEvaluator.Instance,
            launcher: new StaticLauncher(connection),
            capabilityDecoder: new CapabilitySnapshotJsonDecoder());

        ProviderSessionBinding binding = CreateBinding();
        await host.StartAsync(binding, CancellationToken.None);

        using var session = (ProviderRpcSession)host.OpenSession(
            package.Manifest.ProviderId,
            CreateSessionOptions(binding),
            new DualComplianceGate());

        // Should not throw
        session.AssertRawSecretEgressPermitted("ExportPrivateKey");
    }

    // ── F6+F7: KeyExportPolicyEnforcer unit tests ────────────

    [Fact]
    public void Enforcer_AllowExplicit_DoesNotThrow()
    {
        KeyExportPolicyEnforcer.EnforcePrivateKeyExport(KeyExportPolicy.AllowExplicit, "TestOp");
    }

    [Fact]
    public void Enforcer_DenyByDefault_WithoutOverride_Throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            KeyExportPolicyEnforcer.EnforcePrivateKeyExport(KeyExportPolicy.DenyByDefault, "TestOp"));

        Assert.Contains("DenyByDefault", ex.Message);
    }

    [Fact]
    public void Enforcer_DenyByDefault_WithOverride_DoesNotThrow()
    {
        KeyExportPolicyEnforcer.EnforcePrivateKeyExport(KeyExportPolicy.DenyByDefault, "TestOp", overrideGranted: true);
    }

    [Fact]
    public void Enforcer_Prohibited_AlwaysThrows_EvenWithOverride()
    {
        var ex = Assert.Throws<InvalidOperationException>(() =>
            KeyExportPolicyEnforcer.EnforcePrivateKeyExport(KeyExportPolicy.Prohibited, "TestOp", overrideGranted: true));

        Assert.Contains("unconditionally prohibited", ex.Message);
    }

    // ── Infrastructure ───────────────────────────────────────

    private static ProviderPackage CreatePackage(ProviderId providerId, ProviderComplianceEnvelope envelope)
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
                ComplianceEnvelope = envelope,
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

    private static MinimalTrackingConnection CreateFullConnection(ProviderPackage package, ProviderComplianceEnvelope envelope)
    {
        ProviderIdentity identity = CreateIdentity(package);
        CapabilitySnapshot snapshot = CapabilitySnapshot.Create(
            identity,
            ImmutableArray.Create(TestFixtures.Classical_Sig(package.Manifest.ProviderId)));

        return new MinimalTrackingConnection(identity, snapshot, envelope);
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

    private sealed class MinimalTrackingConnection : IProviderConnection
    {
        private readonly ProviderIdentity _identity;
        private readonly ProviderComplianceEnvelope _helloEnvelope;
        private readonly byte[] _capabilityCanonicalBytes;
        private readonly byte[] _capabilityHashSha384;

        public MinimalTrackingConnection(
            ProviderIdentity identity,
            CapabilitySnapshot snapshot,
            ProviderComplianceEnvelope helloEnvelope)
        {
            _identity = identity;
            _helloEnvelope = helloEnvelope;
            _capabilityCanonicalBytes = snapshot.GetCanonicalBytes();
            _capabilityHashSha384 = snapshot.CapabilityHashSha384.Span.ToArray();
        }

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

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

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
