using System;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderHost.Launch;

/// <summary>
/// Canonical launch-time transport budget carried with the launch context.
/// Wave 3 makes the budget operational and adds chunk-planning helpers so oversize
/// requests fail closed with a precise, chunking-aware diagnostic.
/// </summary>
public sealed record OopTransportBudget(
    int ControlMessageBytes,
    int CapabilitySnapshotBytes,
    int PayloadBytes,
    int ChunkSizeBytes)
{
    public const int DefaultControlMessageBytes = 64 * 1024;
    public const int DefaultCapabilitySnapshotBytes = 256 * 1024;
    public const int DefaultChunkSizeBytes = 64 * 1024;

    public void Validate()
    {
        if (ControlMessageBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(ControlMessageBytes));
        if (CapabilitySnapshotBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(CapabilitySnapshotBytes));
        if (PayloadBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(PayloadBytes));
        if (ChunkSizeBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(ChunkSizeBytes));
        if (ChunkSizeBytes > PayloadBytes)
            throw new ArgumentOutOfRangeException(nameof(ChunkSizeBytes), "ChunkSizeBytes must not exceed PayloadBytes.");
    }

    public bool RequiresChunking(int payloadBytes)
        => payloadBytes > PayloadBytes;

    public int GetRequiredChunkCount(int payloadBytes)
    {
        if (payloadBytes <= 0)
            return 0;

        return checked((payloadBytes + ChunkSizeBytes - 1) / ChunkSizeBytes);
    }

    public static OopTransportBudget ForProfile(ExecutionProfile profile, OopTransportLimits? limits)
    {
        int inlineMessageBudget = int.MaxValue;
        if (limits?.MaxReceiveMessageSizeBytes is int maxReceive && maxReceive > 0)
            inlineMessageBudget = Math.Min(inlineMessageBudget, maxReceive);
        if (limits?.MaxSendMessageSizeBytes is int maxSend && maxSend > 0)
            inlineMessageBudget = Math.Min(inlineMessageBudget, maxSend);

        int payloadBytes = profile switch
        {
            ExecutionProfile.Dev => 1024 * 1024,
            ExecutionProfile.Staging => 512 * 1024,
            ExecutionProfile.Prod => 256 * 1024,
            _ => 256 * 1024
        };

        if (inlineMessageBudget != int.MaxValue)
            payloadBytes = Math.Min(payloadBytes, inlineMessageBudget);

        int controlBytes = inlineMessageBudget == int.MaxValue
            ? DefaultControlMessageBytes
            : Math.Min(DefaultControlMessageBytes, inlineMessageBudget);

        int capabilityBytes = inlineMessageBudget == int.MaxValue
            ? DefaultCapabilitySnapshotBytes
            : Math.Min(DefaultCapabilitySnapshotBytes, inlineMessageBudget);

        int chunkSizeBytes = Math.Min(DefaultChunkSizeBytes, payloadBytes);

        var budget = new OopTransportBudget(
            ControlMessageBytes: controlBytes,
            CapabilitySnapshotBytes: capabilityBytes,
            PayloadBytes: payloadBytes,
            ChunkSizeBytes: chunkSizeBytes);

        budget.Validate();
        return budget;
    }
}
