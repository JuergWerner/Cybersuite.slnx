using System;
using System.Collections.Immutable;
using System.Threading;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.ProviderHost.Launch;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Holds the live session state for a single provider connection, including
/// the transcript hash, channel-binding value, policy hash, and a monotonic
/// request counter. Created after a successful handshake and used to stamp
/// every subsequent <see cref="Cybersuite.OopProtocol.Headers.OopRequestHeader"/>
/// with replay-resistant, channel-bound metadata.
///
/// Wave 2 adds a provider-local operation gate so synchronous session APIs remain
/// thread-safe even when the underlying provider connection is not internally synchronized.
/// Wave 3 adds the canonical transport budget used for fail-closed payload enforcement.
/// </summary>
internal sealed class LiveProviderSessionState
{
    private long _counter;
    private readonly object _operationGate = new();
    private int _stopRequested;

    public ProviderId ProviderId { get; }
    public IProviderConnection Connection { get; }
    public ImmutableArray<byte> PolicyHashSha384 { get; }
    public ImmutableArray<byte> TranscriptHashSha384 { get; }
    public ImmutableArray<byte> ChannelBindingSha384 { get; }
    public OopTransportBudget TransportBudget { get; }

    internal object OperationSyncRoot => _operationGate;

    private LiveProviderSessionState(
        ProviderId providerId,
        IProviderConnection connection,
        ImmutableArray<byte> policyHashSha384,
        ImmutableArray<byte> transcriptHashSha384,
        ImmutableArray<byte> channelBindingSha384,
        OopTransportBudget transportBudget)
    {
        ProviderId = providerId;
        Connection = connection;
        PolicyHashSha384 = policyHashSha384;
        TranscriptHashSha384 = transcriptHashSha384;
        ChannelBindingSha384 = channelBindingSha384;
        TransportBudget = transportBudget;
        _counter = 0;
    }

    public static LiveProviderSessionState Create(
        IProviderConnection connection,
        ClientHello clientHello,
        ProviderHello providerHello,
        OopTransportBudget transportBudget)
    {
        ArgumentNullException.ThrowIfNull(connection);
        ArgumentNullException.ThrowIfNull(transportBudget);
        transportBudget.Validate();

        byte[] transcript = HandshakeTranscript.ComputeTranscriptHashSha384(clientHello, providerHello);
        byte[] channelBinding = HandshakeTranscript.ComputeChannelBindingSha384(transcript);

        return new LiveProviderSessionState(
            providerId: providerHello.Identity.ProviderId,
            connection: connection,
            policyHashSha384: ImmutableArray.CreateRange(clientHello.PolicyHashSha384.ToArray()),
            transcriptHashSha384: ImmutableArray.CreateRange(transcript),
            channelBindingSha384: ImmutableArray.CreateRange(channelBinding),
            transportBudget: transportBudget);
    }

    public OopRequestHeader NewRequestHeader(OopMessageType messageType)
    {
        long raw = Interlocked.Increment(ref _counter);

        // SEC-M-007: Detect overflow of the monotonic counter. A signed long overflow
        // after Interlocked.Increment wraps to long.MinValue (negative). In practice
        // this requires 2^63 requests (~292 billion years at 1 billion req/s), but
        // we guard against it for correctness.
        if (raw <= 0)
            throw new InvalidOperationException("Session message counter overflow detected.");

        ulong counter = (ulong)raw;

        return new OopRequestHeader(
            version: ProtocolVersion.V1_0,
            messageType: messageType,
            requestId: Handle128.NewRandom(),
            messageCounter: counter,
            channelBindingSha384: ChannelBindingSha384.AsSpan());
    }

    public bool ValidatePolicyHash(ReadOnlySpan<byte> policyHashSha384)
        => OopFixedTime.FixedTimeEqualsSha384(PolicyHashSha384.AsSpan(), policyHashSha384);

    public void MarkStopping()
    {
        lock (_operationGate)
        {
            Volatile.Write(ref _stopRequested, 1);
        }
    }

    public void ThrowIfStopping()
    {
        if (Volatile.Read(ref _stopRequested) != 0)
            throw new InvalidOperationException("Provider session is stopping or already stopped.");
    }
}
