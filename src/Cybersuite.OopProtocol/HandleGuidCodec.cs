using System;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Utility codec that converts between <see cref="Guid"/> and <see cref="Handle128"/>.
/// This allows callers to use the standard .NET <see cref="Guid"/> type when generating
/// opaque handles while transmitting them as 128-bit fixed-width values on the wire.
/// </summary>
public static class HandleGuidCodec
{
    public static Handle128 FromGuid(Guid guid)
    {
        Span<byte> bytes = stackalloc byte[16];
        guid.TryWriteBytes(bytes);
        return Handle128.FromBytes(bytes);
    }

    public static Guid ToGuid(Handle128 handle)
    {
        Span<byte> bytes = stackalloc byte[16];
        handle.WriteBytes(bytes);
        return new Guid(bytes);
    }
}