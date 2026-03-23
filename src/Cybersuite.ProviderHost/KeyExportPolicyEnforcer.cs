using System;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderHost;

/// <summary>
/// F6-FIX: Centralized enforcement of <see cref="KeyExportPolicy"/> for private key export operations.
/// All export paths must call <see cref="EnforcePrivateKeyExport"/> before releasing secret key material.
///
/// Enforcement rules:
/// <list type="bullet">
///   <item><see cref="KeyExportPolicy.AllowExplicit"/>: Export proceeds — the caller has explicitly opted in.</item>
///   <item><see cref="KeyExportPolicy.DenyByDefault"/>: Export is rejected unless <paramref name="overrideGranted"/>
///         is true (e.g., administrator exemption or policy override token present).</item>
///   <item><see cref="KeyExportPolicy.Prohibited"/>: Export is unconditionally rejected (fail-closed).
///         No override can bypass this level.</item>
/// </list>
/// </summary>
internal static class KeyExportPolicyEnforcer
{
    /// <summary>
    /// Validates that the requested private key export is admissible under the given policy.
    /// Throws <see cref="InvalidOperationException"/> if the export is denied.
    /// </summary>
    /// <param name="policy">The export policy in effect.</param>
    /// <param name="operation">Human-readable operation name for the error message (e.g., "ExportPrivateKey").</param>
    /// <param name="overrideGranted">
    /// When <see langword="true"/>, allows export under <see cref="KeyExportPolicy.DenyByDefault"/>.
    /// Has no effect when the policy is <see cref="KeyExportPolicy.Prohibited"/>.
    /// </param>
    /// <exception cref="InvalidOperationException">Thrown when the export is denied by policy.</exception>
    internal static void EnforcePrivateKeyExport(KeyExportPolicy policy, string operation, bool overrideGranted = false)
    {
        switch (policy)
        {
            case KeyExportPolicy.AllowExplicit:
                return;

            case KeyExportPolicy.DenyByDefault:
                if (overrideGranted)
                    return;
                throw new InvalidOperationException(
                    $"{operation}: Private key export denied by policy (DenyByDefault). " +
                    "An explicit policy override is required to export private key material in this profile.");

            case KeyExportPolicy.Prohibited:
                throw new InvalidOperationException(
                    $"{operation}: Private key export is unconditionally prohibited by policy. " +
                    "No override can bypass this restriction in the current execution profile.");

            default:
                throw new InvalidOperationException(
                    $"{operation}: Unknown KeyExportPolicy '{policy}'. Export denied fail-closed.");
        }
    }
}
