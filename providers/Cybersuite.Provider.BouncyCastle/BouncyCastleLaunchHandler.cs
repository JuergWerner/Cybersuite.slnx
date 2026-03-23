using System;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Concrete launch handler for the managed Bouncy Castle provider.
/// Wave 4 supports two truthful modes only:
/// - Dev/reference: in-process binding with the experimental catalog.
/// - Production-isolated: out-of-process worker with classical-only catalog.
///
/// It deliberately does not claim a validated/FIPS boundary for the managed provider path.
/// </summary>
public sealed class BouncyCastleLaunchHandler : IProviderLaunchHandler
{
    public bool CanLaunch(ProviderPackage package, ProviderLaunchContext launchContext)
    {
        if (package is null || launchContext is null)
            return false;

        if (!package.Manifest.ProviderId.Equals(BouncyCastleProviderIds.ProviderId))
            return false;

        ProviderComplianceEnvelope envelope = package.Manifest.ComplianceEnvelope;

        bool devReferenceAllowed =
            package.Manifest.IsolationMode == ProviderIsolationMode.InProcess &&
            launchContext.Profile == ExecutionProfile.Dev &&
            launchContext.RequiredBoundaryClass == RequiredBoundaryClass.None &&
            launchContext.TargetSecurityClass == ProviderSecurityClass.ReferenceInProcess &&
            envelope.SecurityClass == ProviderSecurityClass.ReferenceInProcess &&
            envelope.BoundaryClass == RequiredBoundaryClass.None;

        if (devReferenceAllowed)
            return true;

        bool productionIsolatedAllowed =
            package.Manifest.IsolationMode == ProviderIsolationMode.OutOfProcess &&
            launchContext.RequiredBoundaryClass == RequiredBoundaryClass.IsolatedProcess &&
            launchContext.TargetSecurityClass == ProviderSecurityClass.ProductionIsolated &&
            envelope.SecurityClass == ProviderSecurityClass.ProductionIsolated &&
            envelope.BoundaryClass >= RequiredBoundaryClass.IsolatedProcess;

        return productionIsolatedAllowed;
    }

    public ValueTask<IProviderConnection> LaunchAsync(
        ProviderPackage package,
        ProviderLaunchContext launchContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!CanLaunch(package, launchContext))
        {
            throw new NotSupportedException(
                "BouncyCastleLaunchHandler only supports the Dev in-process reference package and the ProductionIsolated out-of-process worker package.");
        }

        return package.Manifest.IsolationMode switch
        {
            ProviderIsolationMode.InProcess => ValueTask.FromResult<IProviderConnection>(new BouncyCastleProviderConnection(package)),
            ProviderIsolationMode.OutOfProcess => BouncyCastleOutOfProcessConnection.LaunchAsync(package, launchContext, cancellationToken),
            _ => throw new NotSupportedException($"Unsupported BouncyCastle isolation mode '{package.Manifest.IsolationMode}'.")
        };
    }
}
