using Xunit;

namespace Cybersuite.Tests.Integration;

public sealed class InjectedTestVectorAssetTests
{
    public static IEnumerable<object[]> ExpectedMlKemVectorFiles()
    {
        yield return new object[] { Path.Combine("TestVectors", "ML-KEM", "ML-KEM-512", "keyGen.json") };
        yield return new object[] { Path.Combine("TestVectors", "ML-KEM", "ML-KEM-512", "encapDecap.json") };
        yield return new object[] { Path.Combine("TestVectors", "ML-KEM", "ML-KEM-768", "keyGen.json") };
        yield return new object[] { Path.Combine("TestVectors", "ML-KEM", "ML-KEM-768", "encapDecap.json") };
        yield return new object[] { Path.Combine("TestVectors", "ML-KEM", "ML-KEM-1024", "keyGen.json") };
        yield return new object[] { Path.Combine("TestVectors", "ML-KEM", "ML-KEM-1024", "encapDecap.json") };
    }

    [Theory]
    [MemberData(nameof(ExpectedMlKemVectorFiles))]
    public void MlKem_Injected_TestVectors_Are_Present_In_Test_Output(string relativePath)
    {
        string absolutePath = Path.Combine(AppContext.BaseDirectory, relativePath);
        Assert.True(File.Exists(absolutePath), $"Expected injected ML-KEM test vector missing: {absolutePath}");
    }
}
