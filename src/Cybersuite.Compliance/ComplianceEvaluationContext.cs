using Cybersuite.Abstractions;

namespace Cybersuite.Compliance;

public readonly record struct ComplianceEvaluationContext(
    ExecutionProfile Profile,
    bool FipsRequired
);