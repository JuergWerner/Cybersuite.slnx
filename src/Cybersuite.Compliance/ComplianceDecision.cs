namespace Cybersuite.Compliance;

public readonly record struct ComplianceDecision(
    bool IsAllowed,
    string Reason
);