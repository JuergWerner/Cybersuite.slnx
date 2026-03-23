using System;
using System.Security.Cryptography;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Provides constant-time comparison primitives for OPP security values.
/// Uses <see cref="CryptographicOperations.FixedTimeEquals"/> to prevent
/// timing side-channel attacks when verifying SHA-384 channel-binding hashes.
/// </summary>
public static class OopFixedTime
{
    public static bool FixedTimeEqualsSha384(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (a.Length != OopConstants.Sha384SizeBytes) return false;
        if (b.Length != OopConstants.Sha384SizeBytes) return false;
        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}