using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.Provider.BouncyCastle;
using Xunit;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// Validates that core cryptographic stores and handles are safe for concurrent use.
/// Exercises parallel add/get/destroy on <see cref="BouncyCastleKeyMaterialStore"/>,
/// concurrent lease operations, and dispose-during-operation races.
/// </summary>
public sealed class ThreadSafetyTests
{
    private static readonly ProviderId TestProvider = new("ThreadTest");
    private const int Parallelism = 32;
    private const int IterationsPerThread = 200;

    // ──────────────────────────────────────────────────────────
    //  Parallel add / get / destroy on BouncyCastleKeyMaterialStore
    // ──────────────────────────────────────────────────────────

    [Fact]
    public void ParallelAddAndLeaseSecretKeys_NoCorruption()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var handles = new ConcurrentBag<SecretKeyHandle>();

        Parallel.For(0, Parallelism, _ =>
        {
            for (int i = 0; i < IterationsPerThread; i++)
            {
                byte[] key = new byte[32];
                RandomNumberGenerator.Fill(key);

                var handle = store.AddSecretKey(TestProvider, key);
                handles.Add(handle);

                using var lease = store.LeaseSecretKey(handle);
                Assert.Equal(32, lease.Length);
                Assert.True(lease.ReadOnlySpan.SequenceEqual(key));
            }
        });

        Assert.Equal(Parallelism * IterationsPerThread, handles.Count);
    }

    [Fact]
    public void ParallelAddAndLeaseSharedSecrets_NoCorruption()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var handles = new ConcurrentBag<SharedSecretHandle>();

        Parallel.For(0, Parallelism, _ =>
        {
            for (int i = 0; i < IterationsPerThread; i++)
            {
                byte[] secret = new byte[48];
                RandomNumberGenerator.Fill(secret);

                var handle = store.AddSharedSecret(TestProvider, secret);
                handles.Add(handle);

                using var lease = store.LeaseSharedSecret(handle);
                Assert.Equal(48, lease.Length);
                Assert.True(lease.ReadOnlySpan.SequenceEqual(secret));
            }
        });

        Assert.Equal(Parallelism * IterationsPerThread, handles.Count);
    }

    [Fact]
    public void ParallelAddAndDestroySecretKeys_NoDeadlock()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var created = new ConcurrentBag<SecretKeyHandle>();

        // Phase 1: add many keys in parallel
        Parallel.For(0, Parallelism * IterationsPerThread, _ =>
        {
            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);
            created.Add(store.AddSecretKey(TestProvider, key));
        });

        // Phase 2: destroy all in parallel
        Parallel.ForEach(created, handle =>
        {
            store.Destroy(handle);
        });

        // Phase 3: all handles should now miss
        foreach (var handle in created)
        {
            Assert.Throws<InvalidOperationException>(() => store.LeaseSecretKey(handle));
        }
    }

    [Fact]
    public void ParallelAddPrivateKeyObjects_UniqueHandles()
    {
        using var store = new BouncyCastleKeyMaterialStore();
        var handles = new ConcurrentBag<PrivateKeyHandle>();

        Parallel.For(0, Parallelism, _ =>
        {
            for (int i = 0; i < IterationsPerThread; i++)
            {
                var handle = store.AddPrivateKeyObject(TestProvider, new object());
                handles.Add(handle);
            }
        });

        // All handles must have unique Guid values
        var guids = new HashSet<Guid>();
        foreach (var handle in handles)
            Assert.True(guids.Add(handle.Value), "Duplicate handle GUID detected.");
    }

    // ──────────────────────────────────────────────────────────
    //  Concurrent SensitiveBufferLease lifecycle
    // ──────────────────────────────────────────────────────────

    [Fact]
    public void ParallelLeaseCopyFromAndDispose_NoPoolCorruption()
    {
        Parallel.For(0, Parallelism * IterationsPerThread, _ =>
        {
            byte[] data = new byte[64];
            RandomNumberGenerator.Fill(data);

            var lease = SensitiveBufferLease.CopyFrom(data);
            Assert.True(lease.ReadOnlySpan.SequenceEqual(data));
            lease.Dispose();
        });
    }

    [Fact]
    public void ConcurrentDispose_SameInstance_IsIdempotent()
    {
        var lease = SensitiveBufferLease.CopyFrom(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        var barrier = new ManualResetEventSlim(false);

        var tasks = new Task[Parallelism];
        for (int i = 0; i < Parallelism; i++)
        {
            tasks[i] = Task.Run(() =>
            {
                barrier.Wait();
                lease.Dispose();
            });
        }

        barrier.Set();
        Task.WaitAll(tasks);

        Assert.Throws<ObjectDisposedException>(() => _ = lease.Span);
    }

    // ──────────────────────────────────────────────────────────
    //  Dispose + operation race
    // ──────────────────────────────────────────────────────────

    [Fact]
    public void StoreDispose_DuringConcurrentAdds_ThrowsOrSucceeds()
    {
        var store = new BouncyCastleKeyMaterialStore();
        var barrier = new ManualResetEventSlim(false);
        var exceptions = new ConcurrentBag<Exception>();

        var addTasks = new Task[Parallelism];
        for (int i = 0; i < Parallelism; i++)
        {
            addTasks[i] = Task.Run(() =>
            {
                barrier.Wait();
                for (int j = 0; j < IterationsPerThread; j++)
                {
                    try
                    {
                        store.AddSecretKey(TestProvider, new byte[32]);
                    }
                    catch (ObjectDisposedException)
                    {
                        // Expected after store dispose
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                }
            });
        }

        var disposeTask = Task.Run(() =>
        {
            barrier.Wait();
            Thread.Sleep(1); // Let adds start
            store.Dispose();
        });

        barrier.Set();
        Task.WaitAll([.. addTasks, disposeTask]);

        // No unexpected exceptions
        Assert.Empty(exceptions);
    }

    [Fact]
    public void StoreDispose_IsIdempotent()
    {
        var store = new BouncyCastleKeyMaterialStore();
        store.AddSecretKey(TestProvider, new byte[32]);
        store.AddSharedSecret(TestProvider, new byte[48]);

        store.Dispose();
        store.Dispose(); // Must not throw

        Assert.Throws<ObjectDisposedException>(() =>
            store.AddSecretKey(TestProvider, new byte[32]));
    }

    // ──────────────────────────────────────────────────────────
    //  SessionHandleTracker concurrent operations
    // ──────────────────────────────────────────────────────────

    [Fact]
    public void SessionHandleTracker_ParallelTrackAndValidate_NoCorruption()
    {
        var tracker = new SessionHandleTracker();
        var handles = new ConcurrentBag<SecretKeyHandle>();

        Parallel.For(0, Parallelism, _ =>
        {
            for (int i = 0; i < IterationsPerThread; i++)
            {
                var handle = new SecretKeyHandle(TestProvider, Guid.NewGuid());
                tracker.Track(handle);
                handles.Add(handle);
            }
        });

        // All handles should validate
        Parallel.ForEach(handles, handle =>
        {
            tracker.ValidateOwnership(handle, "test");
        });
    }

    [Fact]
    public void SessionHandleTracker_DrainDuringTrack_FailsClosed()
    {
        var tracker = new SessionHandleTracker();
        var barrier = new ManualResetEventSlim(false);
        var exceptions = new ConcurrentBag<Exception>();

        var trackTasks = new Task[Parallelism];
        for (int i = 0; i < Parallelism; i++)
        {
            trackTasks[i] = Task.Run(() =>
            {
                barrier.Wait();
                for (int j = 0; j < IterationsPerThread; j++)
                {
                    try
                    {
                        tracker.Track(new SecretKeyHandle(TestProvider, Guid.NewGuid()));
                    }
                    catch (ObjectDisposedException)
                    {
                        // Expected after drain
                    }
                    catch (Exception ex)
                    {
                        exceptions.Add(ex);
                    }
                }
            });
        }

        var drainTask = Task.Run(() =>
        {
            barrier.Wait();
            Thread.Sleep(1);
            tracker.DrainAll();
        });

        barrier.Set();
        Task.WaitAll([.. trackTasks, drainTask]);

        Assert.Empty(exceptions);
        Assert.True(tracker.IsDrained);
    }
}
