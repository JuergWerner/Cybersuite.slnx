using System;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Represents a fatal violation of the Out-of-Process Protocol (OPP) contract.
/// Thrown when a message is malformed, a security invariant is breached,
/// or the protocol state machine reaches an irrecoverable state.
/// Follows the fail-closed principle: any protocol error terminates the session.
/// </summary>
public sealed class OopProtocolException : Exception
{
    public OopProtocolException(string message) : base(message) { }
}