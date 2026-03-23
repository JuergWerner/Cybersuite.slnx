using System;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Immutable, comparable version identifier for the Out-of-Process Protocol (OPP) wire format.
/// Exchanged during the handshake phase (ClientHello / ProviderHello) to negotiate
/// the protocol revision used for the session. Major version changes indicate
/// breaking wire-format changes; minor changes add backward-compatible extensions.
/// </summary>
public readonly record struct ProtocolVersion(ushort Major, ushort Minor) : IComparable<ProtocolVersion>
{
    public static readonly ProtocolVersion V1_0 = new(1, 0);

    public int CompareTo(ProtocolVersion other)
    {
        int c = Major.CompareTo(other.Major);
        if (c != 0) return c;
        return Minor.CompareTo(other.Minor);
    }

    public override string ToString() => $"{Major}.{Minor}";
}