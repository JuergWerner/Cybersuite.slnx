using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.ProviderHost.Trust;

public interface IProviderReleaseVerifier
{
    ValueTask<ProviderReleaseVerificationResult> VerifyAsync(
        ProviderPackage package,
        ProviderHostOptions options,
        CancellationToken cancellationToken);
}
