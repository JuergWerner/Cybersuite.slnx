using System.Collections.Immutable;
using System.Threading;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Thread-safe, lock-free registry of active provider records.
/// Uses <see cref="System.Collections.Immutable.ImmutableInterlocked"/> for safe concurrent
/// upsert/remove operations. Callers read a consistent <see cref="ProviderRegistrySnapshot"/>
/// at any time without blocking writers.
/// </summary>
public sealed class ProviderRegistry
{
    private ImmutableDictionary<ProviderId, ProviderRecord> _providers =
        ImmutableDictionary<ProviderId, ProviderRecord>.Empty;

    public ProviderRegistrySnapshot Snapshot => new(Volatile.Read(ref _providers));

    public void Upsert(ProviderId providerId, ProviderRecord record)
    {
        ImmutableInterlocked.AddOrUpdate(
            ref _providers,
            providerId,
            record,
            (_, __) => record);
    }

    public bool TryRemove(ProviderId providerId)
        => ImmutableInterlocked.TryRemove(ref _providers, providerId, out _);
}