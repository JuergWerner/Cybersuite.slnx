namespace Cybersuite.Abstractions;

/// <summary>
/// Immutable export options for key material.
/// Export of private keys may be rejected by provider policy/compliance profile.
/// The <see cref="ExportPolicy"/> field controls whether private key export is admitted at all.
/// </summary>
public readonly record struct KeyExportOptions(
    AlgorithmId AlgorithmId,
    AlgorithmParameterSetId? ParameterSetId,
    AlgorithmEncodingProfile EncodingProfile,
    KeyExportPolicy ExportPolicy = KeyExportPolicy.AllowExplicit
)
{
    /// <summary>
    /// Derives the recommended <see cref="KeyExportPolicy"/> for the given execution profile.
    /// Dev → <see cref="KeyExportPolicy.AllowExplicit"/>,
    /// Staging → <see cref="KeyExportPolicy.DenyByDefault"/>,
    /// Prod → <see cref="KeyExportPolicy.Prohibited"/>.
    /// </summary>
    public static KeyExportPolicy DefaultPolicyForProfile(ExecutionProfile profile) =>
        profile switch
        {
            ExecutionProfile.Dev => KeyExportPolicy.AllowExplicit,
            ExecutionProfile.Staging => KeyExportPolicy.DenyByDefault,
            ExecutionProfile.Prod => KeyExportPolicy.Prohibited,
            _ => KeyExportPolicy.Prohibited // fail-closed for unknown profiles
        };
}