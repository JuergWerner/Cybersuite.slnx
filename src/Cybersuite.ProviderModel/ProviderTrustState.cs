namespace Cybersuite.ProviderModel;

/// <summary>
/// Trust state as evaluated by ProviderHost using allowlists/hashes/signatures/attestation.
/// </summary>
public enum ProviderTrustState
{
    /// <summary>Trust state has not yet been evaluated (initial state before trust pipeline runs).</summary>
    Unknown = 0,

    /// <summary>Provider failed trust evaluation (rejected by allowlist, hash mismatch, provenance/release failure).</summary>
    Untrusted = 1,

    /// <summary>Provider passed all applicable trust gates and is admitted for operation.</summary>
    Trusted = 2,

    /// <summary>Provider was previously trusted but is now quarantined due to a runtime failure or revocation.</summary>
    Quarantined = 3
}