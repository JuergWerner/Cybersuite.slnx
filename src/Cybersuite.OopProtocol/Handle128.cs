using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Cybersuite.OopProtocol;

/// <summary>
/// 128-bit opaque handle used as request ID, instance handle, and secret-reference token
/// throughout the Out-of-Process Protocol (OPP) wire format [OOP-040].
///
/// <b>Security properties:</b>
/// <list type="bullet">
///   <item>Not raw secret material, but treated as a sensitive identifier — avoid logging.</item>
///   <item><see cref="ToString"/> returns a redacted placeholder to prevent accidental exposure.</item>
///   <item><see cref="Equals(Handle128)"/> uses fixed-time XOR comparison to prevent timing side-channels.</item>
///   <item>Generated via <see cref="System.Security.Cryptography.RandomNumberGenerator"/> (CSPRNG).</item>
/// </list>
///
/// <b>Wire encoding:</b> 16 bytes, big-endian canonical (high 8 bytes followed by low 8 bytes).
/// </summary>
public readonly struct Handle128 : IEquatable<Handle128>
{
    /// <summary>Upper 64 bits of the 128-bit handle (big-endian canonical order).</summary>
    public ulong High { get; }

    /// <summary>Lower 64 bits of the 128-bit handle (big-endian canonical order).</summary>
    public ulong Low { get; }

    /// <summary>
    /// Creates a handle from explicit high/low 64-bit halves.
    /// </summary>
    /// <param name="high">Upper 64 bits.</param>
    /// <param name="low">Lower 64 bits.</param>
    public Handle128(ulong high, ulong low)
    {
        High = high;
        Low = low;
    }

    /// <summary>
    /// Generates a cryptographically random 128-bit handle using the OS CSPRNG.
    /// </summary>
    /// <returns>A fresh, unique handle suitable for request IDs and resource references.</returns>
    public static Handle128 NewRandom()
    {
        Span<byte> b = stackalloc byte[OopConstants.HandleSizeBytes];
        RandomNumberGenerator.Fill(b);
        return FromBytes(b);
    }

    /// <summary>
    /// Deserializes a handle from exactly 16 bytes in big-endian canonical order.
    /// </summary>
    /// <param name="bytes16">Exactly 16 bytes containing the serialized handle.</param>
    /// <returns>The deserialized handle.</returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="bytes16"/> is not exactly 16 bytes.</exception>
    public static Handle128 FromBytes(ReadOnlySpan<byte> bytes16)
    {
        if (bytes16.Length != OopConstants.HandleSizeBytes)
            throw new ArgumentException("Handle128 requires exactly 16 bytes.", nameof(bytes16));

        // Big-endian canonical
        ulong high = BinaryPrimitives.ReadUInt64BigEndian(bytes16[..8]);
        ulong low = BinaryPrimitives.ReadUInt64BigEndian(bytes16[8..]);
        return new Handle128(high, low);
    }

    /// <summary>
    /// Serializes this handle into exactly 16 bytes in big-endian canonical order.
    /// </summary>
    /// <param name="dest16">Destination buffer of exactly 16 bytes.</param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="dest16"/> is not exactly 16 bytes.</exception>
    public void WriteBytes(Span<byte> dest16)
    {
        if (dest16.Length != OopConstants.HandleSizeBytes)
            throw new ArgumentException("Destination must be exactly 16 bytes.", nameof(dest16));

        BinaryPrimitives.WriteUInt64BigEndian(dest16[..8], High);
        BinaryPrimitives.WriteUInt64BigEndian(dest16[8..], Low);
    }

    public bool Equals(Handle128 other) => FixedTimeEquals(other);

    /// <summary>
    /// Compares two handles in constant time using XOR aggregation over all 128 bits.
    /// Prevents timing side-channel attacks when validating request or resource IDs.
    /// </summary>
    /// <param name="other">The handle to compare against.</param>
    /// <returns><c>true</c> if all 128 bits are identical; <c>false</c> otherwise.</returns>
    public bool FixedTimeEquals(Handle128 other)
    {
        // Constant-time over 128 bits using xor aggregation
        ulong x = High ^ other.High;
        ulong y = Low ^ other.Low;
        return (x | y) == 0UL;
    }

    public override bool Equals(object? obj) => obj is Handle128 h && Equals(h);

    public override int GetHashCode() => HashCode.Combine(High, Low);

    public static bool operator ==(Handle128 a, Handle128 b) => a.Equals(b);
    public static bool operator !=(Handle128 a, Handle128 b) => !a.Equals(b);

    /// <summary>
    /// Returns a redacted placeholder string to prevent accidental exposure of handle values in logs.
    /// </summary>
    public override string ToString() => "Handle128(REDACTED)";
}