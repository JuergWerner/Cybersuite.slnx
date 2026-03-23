namespace Cybersuite.Abstractions;

/// <summary>
/// F6-FIX: Export governance policy for private key material.
/// Controls whether private key export is allowed, restricted, or prohibited.
///
/// Recommended default matrix by execution profile:
/// <list type="table">
///   <listheader><term>Profile</term><description>Policy</description></listheader>
///   <item><term>Dev</term><description><see cref="AllowExplicit"/> — export permitted when explicitly requested.</description></item>
///   <item><term>Staging</term><description><see cref="DenyByDefault"/> — export denied unless overridden.</description></item>
///   <item><term>Prod</term><description><see cref="Prohibited"/> — private key export unconditionally forbidden.</description></item>
///   <item><term>Regulated/FIPS</term><description><see cref="Prohibited"/> — private key export not admissible.</description></item>
/// </list>
/// </summary>
public enum KeyExportPolicy
{
    /// <summary>
    /// Export is allowed when explicitly requested by the caller.
    /// Suitable for development and testing scenarios.
    /// </summary>
    AllowExplicit = 0,

    /// <summary>
    /// Export is denied by default. The caller must provide an explicit override
    /// (e.g., a policy exemption token or administrator approval context) to proceed.
    /// Suitable for staging environments.
    /// </summary>
    DenyByDefault = 1,

    /// <summary>
    /// Private key export is unconditionally prohibited.
    /// Any attempt to export private key material will be rejected fail-closed.
    /// Suitable for production and regulated/FIPS environments.
    /// </summary>
    Prohibited = 2
}
