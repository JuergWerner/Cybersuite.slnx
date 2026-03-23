using System;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Raised when an inline request or response exceeds the current provider transport budget.
/// Wave 3 uses this as the fail-closed path until chunking/streaming is implemented.
/// </summary>
public sealed class OopTransportBudgetExceededException : InvalidOperationException
{
    public OopTransportBudgetExceededException(
        string operation,
        string direction,
        int actualBytes,
        int maxInlineBytes,
        int suggestedChunkCount)
        : base($"{operation} {direction} payload of {actualBytes} bytes exceeds the inline transport budget of {maxInlineBytes} bytes. Chunking/streaming is not active on this path yet; split the payload or use a transport that supports chunking. Suggested chunks: {suggestedChunkCount}.")
    {
        Operation = operation;
        Direction = direction;
        ActualBytes = actualBytes;
        MaxInlineBytes = maxInlineBytes;
        SuggestedChunkCount = suggestedChunkCount;
    }

    public string Operation { get; }
    public string Direction { get; }
    public int ActualBytes { get; }
    public int MaxInlineBytes { get; }
    public int SuggestedChunkCount { get; }
}
