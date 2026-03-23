namespace Cybersuite.Abstractions;

/// <summary>
/// Represents the security strength of a cryptographic algorithm in bits (e.g. 128, 192, 256).
/// This is the core metric for policy-driven minimum-strength enforcement [ARC-201].
/// The Selection layer uses SecurityStrength to filter algorithms that meet the policy-mandated
/// minimum for each <see cref="AlgorithmCategory"/>. Must be positive; validated at construction.
/// Implements <see cref="IComparable{SecurityStrength}"/> for deterministic strength ordering.
/// </summary>
public readonly record struct SecurityStrength : IComparable<SecurityStrength>
{
    public int Bits { get; }

    public SecurityStrength(int Bits)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(Bits);
        this.Bits = Bits;
    }

    public int CompareTo(SecurityStrength other) => Bits.CompareTo(other.Bits);

    public static bool operator >=(SecurityStrength a, SecurityStrength b)
        => a.Bits >= b.Bits;

    public static bool operator <=(SecurityStrength a, SecurityStrength b)
        => a.Bits <= b.Bits;

    public static bool operator >(SecurityStrength a, SecurityStrength b)
        => a.Bits > b.Bits;

    public static bool operator <(SecurityStrength a, SecurityStrength b)
        => a.Bits < b.Bits;
}