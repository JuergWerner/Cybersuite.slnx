using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.Runtime;

/// <summary>
/// Receives runtime audit events. Events must not contain secret material.
/// </summary>
public interface IRuntimeAuditSink
{
    ValueTask WriteAsync(RuntimeAuditEvent auditEvent, CancellationToken cancellationToken);
}