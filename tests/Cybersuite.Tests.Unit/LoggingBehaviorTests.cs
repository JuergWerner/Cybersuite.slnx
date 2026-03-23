using System.Text;
using Cybersuite.Abstractions;
using Cybersuite.Policy;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// USA-003: Verifies that ILogger integration works correctly across the Cybersuite pipeline.
/// Key invariants:
/// - NullLogger fallback: all components work without a logger (backward compatibility)
/// - Structured logging: log messages contain expected structured parameters
/// - No secret leakage: log messages never contain key material, handles, or raw policy bytes
/// </summary>
public sealed class LoggingBehaviorTests
{
    // Minimal valid policy JSON for testing
    private static readonly byte[] MinimalPolicyUtf8 = Encoding.UTF8.GetBytes("""
    {
        "schemaVersion": "1.0",
        "sequence": 42,
        "securityMode": "Classical",
        "minimumStrengthByCategory": {
            "KeyEncapsulation": 128,
            "Signature": 128
        }
    }
    """);

    private static PolicyLoadOptions DevOptions => new(
        profile: ExecutionProfile.Dev,
        maxPolicyBytes: 1024 * 1024,
        minimumAcceptedSequence: 0,
        requireSignatureVerification: false,
        requireProviderAllowlist: false,
        expectedPolicyHashSha384: default,
        signatureVerifier: null,
        signatureVerificationOptions: PolicySignatureVerificationOptions.Default);

    // ─────────────────────────────────────────────────────────
    //  PolicyLoader logging
    // ─────────────────────────────────────────────────────────

    [Fact]
    public void PolicyLoader_WithLogger_EmitsSnapshotCreatedLog()
    {
        var logger = new FakeLogger();

        PolicyLoader.LoadFromBytes(MinimalPolicyUtf8, DevOptions, logger);

        Assert.True(logger.HasEntries, "Logger should have captured log entries");
        Assert.True(logger.HasLogLevel(LogLevel.Information), "Should have Information-level log");
        Assert.True(logger.ContainsMessage("snapshot created"), "Should log snapshot creation");
        Assert.True(logger.ContainsMessage("sequence="), "Should include structured sequence parameter");
    }

    [Fact]
    public void PolicyLoader_WithLogger_EmitsParsedLog()
    {
        var logger = new FakeLogger();

        PolicyLoader.LoadFromBytes(MinimalPolicyUtf8, DevOptions, logger);

        Assert.True(logger.HasLogLevel(LogLevel.Debug), "Should have Debug-level parse log");
        Assert.True(logger.ContainsMessage("parsed"), "Should log policy parsed event");
    }

    [Fact]
    public void PolicyLoader_WithNullLogger_WorksWithoutException()
    {
        // Backward compatibility: null logger must not cause any exception
        var snapshot = PolicyLoader.LoadFromBytes(MinimalPolicyUtf8, DevOptions, logger: null);

        Assert.Equal("1.0", snapshot.SchemaVersion);
        Assert.Equal(42, snapshot.Sequence);
    }

    [Fact]
    public void PolicyLoader_LogMessages_DoNotContainRawPolicyBytes()
    {
        var logger = new FakeLogger();

        PolicyLoader.LoadFromBytes(MinimalPolicyUtf8, DevOptions, logger);

        string allMessages = string.Join(" ", logger.Entries.Select(e => e.Message));

        // Must never log raw policy content or cryptographic material
        Assert.DoesNotContain("schemaVersion", allMessages);
        Assert.DoesNotContain("securityMode\":\"classical", allMessages);
    }

    // ─────────────────────────────────────────────────────────
    //  DefaultProviderTrustEvaluator logging
    // ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TrustEvaluator_WithLogger_LogsAcceptance()
    {
        var logger = new FakeLogger<DefaultProviderTrustEvaluator>();
        var evaluator = new DefaultProviderTrustEvaluator(logger);

        var package = CreateTestProviderPackage("TestProvider");
        var options = CreateDevHostOptions();

        var decision = await evaluator.EvaluateAsync(package, options, CancellationToken.None);

        Assert.True(decision.IsTrusted);
        Assert.True(logger.HasLogLevel(LogLevel.Debug), "Should log debug on trust acceptance");
        Assert.True(logger.ContainsMessage("accepted"), "Should log trust acceptance");
        Assert.True(logger.ContainsMessage("TestProvider"), "Should include provider ID");
    }

    [Fact]
    public async Task TrustEvaluator_WhenRejected_LogsWarning()
    {
        var logger = new FakeLogger<DefaultProviderTrustEvaluator>();
        var evaluator = new DefaultProviderTrustEvaluator(logger);

        var package = CreateTestProviderPackage("UnknownProvider");
        // Options with a non-empty allowlist that does NOT include "UnknownProvider"
        var options = CreateHostOptionsWithAllowlist(new ProviderId("AllowedOnly"));

        var decision = await evaluator.EvaluateAsync(package, options, CancellationToken.None);

        Assert.False(decision.IsTrusted);
        Assert.True(logger.HasLogLevel(LogLevel.Warning), "Should log warning on trust rejection");
        Assert.True(logger.ContainsMessage("rejected"), "Should log rejection reason");
        Assert.True(logger.ContainsMessage("UnknownProvider"), "Should include rejected provider ID");
    }

    [Fact]
    public async Task TrustEvaluator_WithNullLogger_WorksWithoutException()
    {
        var evaluator = new DefaultProviderTrustEvaluator(logger: null);
        var package = CreateTestProviderPackage("TestProvider");
        var options = CreateDevHostOptions();

        var decision = await evaluator.EvaluateAsync(package, options, CancellationToken.None);

        Assert.True(decision.IsTrusted);
    }

    // ─────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────

    private static ProviderPackage CreateTestProviderPackage(string providerId)
    {
        return new ProviderPackage
        {
            Manifest = new ProviderManifest
            {
                ProviderId = new ProviderId(providerId),
                Version = "1.0.0",
                Vendor = "TestVendor",
                IsolationMode = ProviderIsolationMode.InProcess,
                IsExperimental = false,
                FipsBoundaryDeclared = false,
                EntrypointSha256Hex = null,
            },
            PackageRoot = ".",
            EntrypointPath = "dummy.dll"
        };
    }

    private static ProviderHostOptions CreateDevHostOptions()
    {
        return new ProviderHostOptions
        {
            ExecutionProfile = ExecutionProfile.Dev,
        };
    }

    private static ProviderHostOptions CreateHostOptionsWithAllowlist(ProviderId allowedId)
    {
        return new ProviderHostOptions
        {
            ExecutionProfile = ExecutionProfile.Dev,
            ProviderIdAllowlist = System.Collections.Immutable.ImmutableHashSet.Create(allowedId),
        };
    }
}
