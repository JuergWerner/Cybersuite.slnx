using System.Collections.Immutable;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Immutable snapshot of the last host start attempt.
/// Contains the terminal transaction state for every discovered provider.
/// </summary>
public sealed record ProviderStartJournal(ImmutableArray<ProviderStartTransaction> Entries)
{
    public static ProviderStartJournal Empty { get; } =
        new(ImmutableArray<ProviderStartTransaction>.Empty);
}

/// <summary>
/// Immutable snapshot of terminal provider failures or rejections captured during host startup.
/// </summary>
public sealed record ProviderFailureJournal(ImmutableArray<ProviderStartTransaction> Entries)
{
    public static ProviderFailureJournal Empty { get; } =
        new(ImmutableArray<ProviderStartTransaction>.Empty);

    public bool HasFailures => !Entries.IsDefaultOrEmpty && Entries.Length > 0;
}
