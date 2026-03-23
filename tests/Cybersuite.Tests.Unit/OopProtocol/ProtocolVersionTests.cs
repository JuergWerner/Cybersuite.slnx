using Cybersuite.OopProtocol;
using Xunit;

namespace Cybersuite.Tests.Unit.OopProtocol;

/// <summary>
/// Tests for ProtocolVersion: comparison, equality, and ToString behavior.
/// </summary>
public sealed class ProtocolVersionTests
{
    [Fact]
    public void V1_0_Predefined()
    {
        Assert.Equal(1, ProtocolVersion.V1_0.Major);
        Assert.Equal(0, ProtocolVersion.V1_0.Minor);
    }

    [Fact]
    public void CompareTo_SameMajor_MinorDecides()
    {
        var a = new ProtocolVersion(1, 0);
        var b = new ProtocolVersion(1, 1);
        Assert.True(a.CompareTo(b) < 0);
        Assert.True(b.CompareTo(a) > 0);
    }

    [Fact]
    public void CompareTo_DifferentMajor_MajorDecides()
    {
        var a = new ProtocolVersion(1, 9);
        var b = new ProtocolVersion(2, 0);
        Assert.True(a.CompareTo(b) < 0);
    }

    [Fact]
    public void ToString_Format()
    {
        Assert.Equal("1.0", ProtocolVersion.V1_0.ToString());
        Assert.Equal("2.3", new ProtocolVersion(2, 3).ToString());
    }
}
