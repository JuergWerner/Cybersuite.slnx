using Cybersuite.Abstractions;
using Cybersuite.Provider.BouncyCastle;
using Xunit;

namespace Cybersuite.Tests.Unit.Providers.BouncyCastle;

public sealed class BouncyCastleKeyMaterialStoreWave3Tests
{
    [Fact]
    public void GetPrivateKeyObject_WithProviderMismatchedHandle_FailsClosed()
    {
        using var store = new BouncyCastleKeyMaterialStore();

        ProviderId providerA = new("ProviderA");
        ProviderId providerB = new("ProviderB");

        PrivateKeyHandle original = store.AddPrivateKeyObject(providerA, new object());
        PrivateKeyHandle mismatched = new(providerB, original.Value);

        var ex = Assert.Throws<InvalidOperationException>(() => store.GetPrivateKeyObject(mismatched));
        Assert.Contains("provider mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetSecretKeyCopy_WithProviderMismatchedHandle_FailsClosed()
    {
        using var store = new BouncyCastleKeyMaterialStore();

        ProviderId providerA = new("ProviderA");
        ProviderId providerB = new("ProviderB");

        SecretKeyHandle original = store.AddSecretKey(providerA, new byte[] { 1, 2, 3, 4 });
        SecretKeyHandle mismatched = new(providerB, original.Value);

        var ex = Assert.Throws<InvalidOperationException>(() => store.LeaseSecretKey(mismatched));
        Assert.Contains("provider mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GetSharedSecretCopy_WithProviderMismatchedHandle_FailsClosed()
    {
        using var store = new BouncyCastleKeyMaterialStore();

        ProviderId providerA = new("ProviderA");
        ProviderId providerB = new("ProviderB");

        SharedSecretHandle original = store.AddSharedSecret(providerA, new byte[] { 9, 8, 7, 6 });
        SharedSecretHandle mismatched = new(providerB, original.Value);

        var ex = Assert.Throws<InvalidOperationException>(() => store.LeaseSharedSecret(mismatched));
        Assert.Contains("provider mismatch", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
