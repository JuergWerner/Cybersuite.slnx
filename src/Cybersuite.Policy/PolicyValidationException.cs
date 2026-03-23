using System;

namespace Cybersuite.Policy;

/// <summary>
/// Thrown when policy loading or validation fails at any gate in the <see cref="PolicyLoader"/> pipeline.
/// Examples: empty policy, size exceeded, sequence rollback, hash mismatch, missing allowlist,
/// or signature verification failure. This is the fail-closed exit path [ARC-400].
/// </summary>
public sealed class PolicyValidationException : Exception
{
    public PolicyValidationException(string message) : base(message) { }

    public PolicyValidationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
