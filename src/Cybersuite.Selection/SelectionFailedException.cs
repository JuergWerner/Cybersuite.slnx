using System;
using Cybersuite.Abstractions;

namespace Cybersuite.Selection;

/// <summary>
/// Thrown by the <see cref="AlgorithmSelector"/> when no algorithm satisfying the policy
/// constraints can be found for a given <see cref="AlgorithmCategory"/>. This is a fail-closed
/// condition: the runtime will not proceed without a valid selection for every required
/// algorithm category [ARC-600]. Carries the failing category for diagnostic purposes.
/// </summary>
public sealed class SelectionFailedException : Exception
{
    public AlgorithmCategory Category { get; }

    public SelectionFailedException(AlgorithmCategory category, string message)
        : base(message)
    {
        Category = category;
    }
}