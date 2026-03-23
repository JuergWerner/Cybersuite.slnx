using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Cybersuite.Abstractions;

namespace Cybersuite.Provider.BouncyCastle;

internal sealed class BouncyCastleKeyMaterialStore : IDisposable
{
    private readonly object _gate = new();
    private bool _disposed;

    // Wave 3: key stores are provider-bound by construction, not just by convention.
    private readonly Dictionary<PrivateKeyHandle, object> _privateKeys = new();
    private readonly Dictionary<SecretKeyHandle, byte[]> _secretKeys = new();
    private readonly Dictionary<SharedSecretHandle, byte[]> _sharedSecrets = new();

    public PrivateKeyHandle AddPrivateKey(ProviderId providerId, ECPrivateKeyParameters privateKey)
        => AddPrivateKeyObject(providerId, privateKey);

    public PrivateKeyHandle AddPrivateKeyObject(ProviderId providerId, object privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        lock (_gate)
        {
            ThrowIfDisposed();
            var handle = new PrivateKeyHandle(providerId, Guid.NewGuid());
            _privateKeys[handle] = privateKey;
            return handle;
        }
    }

    public ECPrivateKeyParameters GetEcPrivateKey(PrivateKeyHandle handle)
        => GetPrivateKey<ECPrivateKeyParameters>(handle);

    public T GetPrivateKey<T>(PrivateKeyHandle handle) where T : class
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (!_privateKeys.TryGetValue(handle, out var key))
                throw new InvalidOperationException(DescribePrivateHandleMiss(handle));

            if (key is not T typed)
                throw new InvalidOperationException($"PrivateKeyHandle does not reference expected type '{typeof(T).FullName}'.");

            return typed;
        }
    }

    public object GetPrivateKeyObject(PrivateKeyHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (!_privateKeys.TryGetValue(handle, out var key))
                throw new InvalidOperationException(DescribePrivateHandleMiss(handle));

            return key;
        }
    }

    public SecretKeyHandle AddSecretKey(ProviderId providerId, ReadOnlySpan<byte> keyBytes)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var handle = new SecretKeyHandle(providerId, Guid.NewGuid());
            _secretKeys[handle] = keyBytes.ToArray();
            return handle;
        }
    }

    public SharedSecretHandle AddSharedSecret(ProviderId providerId, ReadOnlySpan<byte> secretBytes)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            var handle = new SharedSecretHandle(providerId, Guid.NewGuid());
            _sharedSecrets[handle] = secretBytes.ToArray();
            return handle;
        }
    }

    /// <summary>
    /// F5-FIX: Returns a <see cref="SensitiveBufferLease"/> containing a pooled copy of the
    /// secret key. The lease auto-zeroizes and returns the buffer to the pool on Dispose.
    /// </summary>
    public SensitiveBufferLease LeaseSecretKey(SecretKeyHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (!_secretKeys.TryGetValue(handle, out var key))
                throw new InvalidOperationException(DescribeSecretHandleMiss(handle));

            return SensitiveBufferLease.CopyFrom(key);
        }
    }

    /// <summary>
    /// F5-FIX: Returns a <see cref="SensitiveBufferLease"/> containing a pooled copy of the
    /// shared secret. The lease auto-zeroizes and returns the buffer to the pool on Dispose.
    /// </summary>
    public SensitiveBufferLease LeaseSharedSecret(SharedSecretHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (!_sharedSecrets.TryGetValue(handle, out var secret))
                throw new InvalidOperationException(DescribeSharedSecretHandleMiss(handle));

            return SensitiveBufferLease.CopyFrom(secret);
        }
    }

    public void Destroy(PrivateKeyHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            _privateKeys.Remove(handle);
        }
    }

    public void Destroy(SecretKeyHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_secretKeys.Remove(handle, out var key))
                CryptographicOperations.ZeroMemory(key);
        }
    }

    public void Destroy(SharedSecretHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            if (_sharedSecrets.Remove(handle, out var secret))
                CryptographicOperations.ZeroMemory(secret);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
                return;

            _disposed = true;

            foreach (var kv in _secretKeys)
                CryptographicOperations.ZeroMemory(kv.Value);

            foreach (var kv in _sharedSecrets)
                CryptographicOperations.ZeroMemory(kv.Value);

            _privateKeys.Clear();
            _secretKeys.Clear();
            _sharedSecrets.Clear();
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private string DescribePrivateHandleMiss(PrivateKeyHandle handle)
        => HasGuidCollision(_privateKeys.Keys.Select(static h => h.Value), handle.Value)
            ? $"PrivateKeyHandle provider mismatch for provider '{handle.ProviderId.Value}'."
            : "PrivateKeyHandle not found.";

    private string DescribeSecretHandleMiss(SecretKeyHandle handle)
        => HasGuidCollision(_secretKeys.Keys.Select(static h => h.Value), handle.Value)
            ? $"SecretKeyHandle provider mismatch for provider '{handle.ProviderId.Value}'."
            : "SecretKeyHandle not found.";

    private string DescribeSharedSecretHandleMiss(SharedSecretHandle handle)
        => HasGuidCollision(_sharedSecrets.Keys.Select(static h => h.Value), handle.Value)
            ? $"SharedSecretHandle provider mismatch for provider '{handle.ProviderId.Value}'."
            : "SharedSecretHandle not found.";

    private static bool HasGuidCollision(IEnumerable<Guid> knownValues, Guid target)
    {
        foreach (Guid value in knownValues)
        {
            if (value == target)
                return true;
        }

        return false;
    }
}
