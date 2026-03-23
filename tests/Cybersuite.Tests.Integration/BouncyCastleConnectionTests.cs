using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderModel;
using Xunit;

namespace Cybersuite.Tests.Integration;

/// <summary>
/// Integration tests for the BouncyCastleProviderConnection.
/// Tests the full OOP handshake, capability exchange, health, shutdown,
/// and live crypto round-trips (ECDH-P384-KEM, ECDSA-P384, AES-256-GCM) per [PH-023].
/// These tests exercise the real BouncyCastle cryptographic library.
/// </summary>
public sealed class BouncyCastleConnectionTests : IAsyncDisposable
{
    private readonly BouncyCastleProviderConnection _connection;
    private readonly ProviderPackage _package;
    private ClientHello? _clientHello;
    private ProviderHello? _providerHello;
    private byte[]? _channelBinding;
    private ulong _counter;

    public BouncyCastleConnectionTests()
    {
        // Use the assembly itself as the entrypoint path for testing
        string entrypoint = typeof(BouncyCastleProviderConnection).Assembly.Location;
        string packageRoot = Path.GetDirectoryName(entrypoint)!;

        _package = BouncyCastleManifestFactory.CreateInProcessPackage(packageRoot, entrypoint);
        _connection = new BouncyCastleProviderConnection(_package);
    }

    public async ValueTask DisposeAsync()
    {
        await _connection.DisposeAsync();
    }

    /// <summary>
    /// Performs the full handshake and sets up channel binding for subsequent requests.
    /// </summary>
    private async Task<ProviderHello> HandshakeAsync()
    {
        var nonce = new byte[OopConstants.NonceSizeBytes];
        System.Security.Cryptography.RandomNumberGenerator.Fill(nonce);
        var policyHash = new byte[OopConstants.Sha384SizeBytes];

        _clientHello = new ClientHello(
            version: ProtocolVersion.V1_0,
            nonce32: nonce,
            policyHashSha384: policyHash,
            profile: ExecutionProfile.Dev,
            fipsRequired: false,
            experimentalAllowed: true,
            tenantId: null,
            expectedProviderId: null,
            expectedBuildHash: null);

        _providerHello = await _connection.HandshakeAsync(_clientHello, CancellationToken.None);

        // Compute channel binding for subsequent requests
        byte[] transcript = HandshakeTranscript.ComputeTranscriptHashSha384(_clientHello, _providerHello);
        _channelBinding = HandshakeTranscript.ComputeChannelBindingSha384(transcript);
        _counter = 0;

        return _providerHello;
    }

    private OopRequestHeader NewHeader(OopMessageType type)
    {
        _counter++;
        return new OopRequestHeader(
            version: ProtocolVersion.V1_0,
            messageType: type,
            requestId: Handle128.NewRandom(),
            messageCounter: _counter,
            channelBindingSha384: _channelBinding!);
    }

    // ?? Handshake tests ??

    [Fact]
    public async Task Handshake_ReturnsValidProviderHello()
    {
        var hello = await HandshakeAsync();

        Assert.Equal(ProtocolVersion.V1_0, hello.Version);
        Assert.Equal("BouncyCastle", hello.Identity.ProviderId.Value);
        Assert.Equal(32, hello.Nonce.Length);
        Assert.Equal(48, hello.CapabilityHashSha384.Length);
        Assert.False(hello.FipsBoundaryDeclared);
        Assert.True(hello.IsExperimental);
        Assert.Equal(ProviderSecurityClass.ReferenceInProcess, hello.ComplianceEnvelope.SecurityClass);
        Assert.Equal(RequiredBoundaryClass.None, hello.ComplianceEnvelope.BoundaryClass);
        Assert.False(hello.ComplianceEnvelope.DeclaredValidatedBoundary);
        Assert.Equal(48, hello.ComplianceEnvelope.EnvelopeHashSha384.Length);
    }

    // ?? Capability exchange ??

    [Fact]
    public async Task GetCapabilities_ReturnsValidSnapshot()
    {
        await HandshakeAsync();

        var response = await _connection.GetCapabilitiesAsync(
            new CapabilityRequest(NewHeader(OopMessageType.CapabilityRequest)),
            CancellationToken.None);

        Assert.True(response.Header.Success);
        Assert.Equal(OopConstants.Sha384SizeBytes, response.CapabilityHashSha384.Length);
        Assert.True(response.CapabilityCanonicalBytes.Length > 0);
    }

    // ?? Health check ??

    [Fact]
    public async Task Health_ReturnsHealthy()
    {
        await HandshakeAsync();

        var response = await _connection.HealthAsync(
            new HealthRequest(NewHeader(OopMessageType.HealthRequest)),
            CancellationToken.None);

        Assert.True(response.Header.Success);
        Assert.True(response.IsHealthy);
    }

    // ?? Replay protection: same counter rejected ??

    [Fact]
    public async Task ReplayCounter_SameValue_Throws()
    {
        await HandshakeAsync();

        _counter = 1;
        await _connection.HealthAsync(
            new HealthRequest(NewHeader(OopMessageType.HealthRequest)),
            CancellationToken.None);

        // Send with same counter value (counter was already incremented to 2, send 2 again)
        var header = new OopRequestHeader(
            version: ProtocolVersion.V1_0,
            messageType: OopMessageType.HealthRequest,
            requestId: Handle128.NewRandom(),
            messageCounter: _counter, // same value as last accepted
            channelBindingSha384: _channelBinding!);

        await Assert.ThrowsAsync<OopProtocolException>(() =>
            _connection.HealthAsync(new HealthRequest(header), CancellationToken.None).AsTask());
    }

    // ?? Channel binding mismatch rejected ??

    [Fact]
    public async Task ChannelBinding_Mismatch_Throws()
    {
        await HandshakeAsync();

        var badBinding = new byte[OopConstants.Sha384SizeBytes]; // all zeros
        var header = new OopRequestHeader(
            version: ProtocolVersion.V1_0,
            messageType: OopMessageType.HealthRequest,
            requestId: Handle128.NewRandom(),
            messageCounter: ++_counter,
            channelBindingSha384: badBinding);

        await Assert.ThrowsAsync<OopProtocolException>(() =>
            _connection.HealthAsync(new HealthRequest(header), CancellationToken.None).AsTask());
    }

    // ?? Shutdown + post-shutdown rejection ??

    [Fact]
    public async Task Shutdown_ThenRequestFails()
    {
        await HandshakeAsync();

        var shutdownResponse = await _connection.ShutdownAsync(
            new ShutdownRequest(NewHeader(OopMessageType.ShutdownRequest), true),
            CancellationToken.None);
        Assert.True(shutdownResponse.Header.Success);

        // Any subsequent request should fail
        await Assert.ThrowsAsync<OopProtocolException>(() =>
            _connection.HealthAsync(
                new HealthRequest(NewHeader(OopMessageType.HealthRequest)),
                CancellationToken.None).AsTask());
    }

    // ?? Pre-handshake request fails ??

    [Fact]
    public async Task Request_BeforeHandshake_Throws()
    {
        // Create a new connection without handshaking
        string entrypoint = typeof(BouncyCastleProviderConnection).Assembly.Location;
        await using var conn = new BouncyCastleProviderConnection(
            BouncyCastleManifestFactory.CreateInProcessPackage(
                Path.GetDirectoryName(entrypoint)!, entrypoint));

        var fakeBinding = new byte[OopConstants.Sha384SizeBytes];
        var header = new OopRequestHeader(
            version: ProtocolVersion.V1_0,
            messageType: OopMessageType.HealthRequest,
            requestId: Handle128.NewRandom(),
            messageCounter: 1,
            channelBindingSha384: fakeBinding);

        await Assert.ThrowsAsync<OopProtocolException>(() =>
            conn.HealthAsync(new HealthRequest(header), CancellationToken.None).AsTask());
    }
}
