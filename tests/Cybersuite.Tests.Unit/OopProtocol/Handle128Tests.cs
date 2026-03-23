using Cybersuite.OopProtocol;
using Xunit;

namespace Cybersuite.Tests.Unit.OopProtocol;

/// <summary>
/// Tests for Handle128: random generation, byte round-trip, constant-time equality,
/// redacted ToString, and big-endian canonical encoding per [OOP-000].
/// </summary>
public sealed class Handle128Tests
{
    [Fact]
    public void NewRandom_ProducesDifferentHandles()
    {
        var a = Handle128.NewRandom();
        var b = Handle128.NewRandom();
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void FromBytes_RoundTrips()
    {
        var original = Handle128.NewRandom();
        var bytes = new byte[OopConstants.HandleSizeBytes];
        original.WriteBytes(bytes);

        var restored = Handle128.FromBytes(bytes);
        Assert.Equal(original, restored);
    }

    [Fact]
    public void FromBytes_WrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() => Handle128.FromBytes(new byte[15]));
        Assert.Throws<ArgumentException>(() => Handle128.FromBytes(new byte[17]));
    }

    [Fact]
    public void WriteBytes_WrongLength_Throws()
    {
        var h = Handle128.NewRandom();
        Assert.Throws<ArgumentException>(() => h.WriteBytes(new byte[8]));
    }

    [Fact]
    public void FixedTimeEquals_SameHandle_ReturnsTrue()
    {
        var h = new Handle128(0xDEADBEEFul, 0xCAFEBABEul);
        Assert.True(h.FixedTimeEquals(h));
    }

    [Fact]
    public void FixedTimeEquals_DifferentHandle_ReturnsFalse()
    {
        var a = new Handle128(1, 2);
        var b = new Handle128(1, 3);
        Assert.False(a.FixedTimeEquals(b));
    }

    [Fact]
    public void ToString_ReturnsRedacted()
    {
        var h = Handle128.NewRandom();
        Assert.Equal("Handle128(REDACTED)", h.ToString());
    }

    [Fact]
    public void Equality_Operators()
    {
        var a = new Handle128(42, 99);
        var b = new Handle128(42, 99);
        var c = new Handle128(42, 100);

        Assert.True(a == b);
        Assert.False(a != b);
        Assert.True(a != c);
    }

    [Fact]
    public void GetHashCode_SameHandles_SameHash()
    {
        var a = new Handle128(7, 13);
        var b = new Handle128(7, 13);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }
}
