using System.Threading;
using System.Threading.Tasks;
using Cybersuite.OopProtocol.Handshake;

namespace Cybersuite.ProviderHost.Trust;

public interface IProviderAttestationVerifier
{
    ValueTask<ProviderAttestationVerificationResult> VerifyAsync(
        ProviderPackage package,
        ProviderHello providerHello,
        ProviderSessionBinding binding,
        ProviderHostOptions options,
        CancellationToken cancellationToken);
}
