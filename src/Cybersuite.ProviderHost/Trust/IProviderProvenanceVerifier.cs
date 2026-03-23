using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.ProviderHost.Trust;

public interface IProviderProvenanceVerifier
{
    ValueTask<ProviderProvenanceVerificationResult> VerifyAsync(
        ProviderPackage package,
        ProviderHostOptions options,
        CancellationToken cancellationToken);
}
