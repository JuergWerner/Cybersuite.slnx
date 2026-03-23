using Cybersuite.Abstractions;

namespace Cybersuite.Runtime;

public sealed record RuntimeOptions
{
    /// <summary>
    /// If true, ProviderHost is stopped when the runtime is disposed.
    /// </summary>
    public bool StopProviderHostOnDispose { get; init; } = true;

    /// <summary>
    /// If true, runtime emits non-secret audit events through the configured audit sink.
    /// </summary>
    public bool EmitAuditEvents { get; init; } = true;

    /// <summary>
    /// Experimental providers are allowed in Dev by default.
    /// </summary>
    public bool AllowExperimentalProvidersInDev { get; init; } = true;

    /// <summary>
    /// Experimental providers are disabled in Staging by default.
    /// </summary>
    public bool AllowExperimentalProvidersInStaging { get; init; } = false;

    /// <summary>
    /// Experimental providers are disabled in Prod by default.
    /// </summary>
    public bool AllowExperimentalProvidersInProd { get; init; } = false;

    public bool IsExperimentalAllowed(ExecutionProfile profile)
        => profile switch
        {
            ExecutionProfile.Dev => AllowExperimentalProvidersInDev,
            ExecutionProfile.Staging => AllowExperimentalProvidersInStaging,
            ExecutionProfile.Prod => AllowExperimentalProvidersInProd,
            _ => false
        };

    public static RuntimeOptions Default { get; } = new();
}