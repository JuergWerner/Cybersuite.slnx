using System.Security.Cryptography;
using Cybersuite.OopProtocol;
using Xunit;

namespace Cybersuite.Tests.Unit.OopProtocol;

/// <summary>
/// Tests for OopFixedTime constant-time comparison per [SEC-SC-000].
/// </summary>
public sealed class OopFixedTimeTests
{
    [Fact]
    public void FixedTimeEqualsSha384_SameBytes_ReturnsTrue()
    {
        var a = new byte[48];
        RandomNumberGenerator.Fill(a);
        Assert.True(OopFixedTime.FixedTimeEqualsSha384(a, a));
    }

    [Fact]
    public void FixedTimeEqualsSha384_DifferentBytes_ReturnsFalse()
    {
        var a = new byte[48];
        var b = new byte[48];
        RandomNumberGenerator.Fill(a);
        RandomNumberGenerator.Fill(b);
        Assert.False(OopFixedTime.FixedTimeEqualsSha384(a, b));
    }

    [Fact]
    public void FixedTimeEqualsSha384_WrongLength_ReturnsFalse()
    {
        Assert.False(OopFixedTime.FixedTimeEqualsSha384(new byte[47], new byte[48]));
        Assert.False(OopFixedTime.FixedTimeEqualsSha384(new byte[48], new byte[49]));
        Assert.False(OopFixedTime.FixedTimeEqualsSha384(new byte[32], new byte[32]));
    }
}
