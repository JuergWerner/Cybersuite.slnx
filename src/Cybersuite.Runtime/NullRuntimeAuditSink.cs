using System.Threading;
using System.Threading.Tasks;

namespace Cybersuite.Runtime;

public sealed class NullRuntimeAuditSink : IRuntimeAuditSink
{
    public static NullRuntimeAuditSink Instance { get; } = new();

    private NullRuntimeAuditSink() { }

    public ValueTask WriteAsync(RuntimeAuditEvent auditEvent, CancellationToken cancellationToken)
        => ValueTask.CompletedTask;
}