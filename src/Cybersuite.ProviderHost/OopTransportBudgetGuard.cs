using System;
using Cybersuite.ProviderHost.Launch;

namespace Cybersuite.ProviderHost;

internal static class OopTransportBudgetGuard
{
    public static void EnsureRequestPayloadWithinBudget(
        OopTransportBudget budget,
        string operation,
        params int[] segments)
        => EnsureWithinBudget(budget, operation, direction: "request", budget.PayloadBytes, segments);

    public static void EnsureResponsePayloadWithinBudget(
        OopTransportBudget budget,
        string operation,
        params int[] segments)
        => EnsureWithinBudget(budget, operation, direction: "response", budget.PayloadBytes, segments);

    public static void EnsureCapabilitySnapshotWithinBudget(
        OopTransportBudget budget,
        int capabilitySnapshotBytes)
        => EnsureWithinBudget(
            budget,
            operation: "CapabilitySnapshot",
            direction: "response",
            maxBytes: budget.CapabilitySnapshotBytes,
            capabilitySnapshotBytes);

    private static void EnsureWithinBudget(
        OopTransportBudget budget,
        string operation,
        string direction,
        int maxBytes,
        params int[] segments)
    {
        if (budget is null)
            throw new ArgumentNullException(nameof(budget));
        if (maxBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxBytes));

        int totalBytes = SumSegments(segments);
        if (totalBytes <= maxBytes)
            return;

        throw new OopTransportBudgetExceededException(
            operation,
            direction,
            actualBytes: totalBytes,
            maxInlineBytes: maxBytes,
            suggestedChunkCount: budget.GetRequiredChunkCount(totalBytes));
    }

    private static int SumSegments(int[] segments)
    {
        if (segments is null || segments.Length == 0)
            return 0;

        int total = 0;
        for (int i = 0; i < segments.Length; i++)
        {
            int segment = segments[i];
            if (segment < 0)
                throw new ArgumentOutOfRangeException(nameof(segments), "Payload segment sizes must be non-negative.");

            total = checked(total + segment);
        }

        return total;
    }
}
