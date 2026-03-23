using System;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Cybersuite.Tests.Unit;

/// <summary>
/// Non-generic version of FakeLogger for use with static classes (e.g., PolicyLoader)
/// that cannot be used as type arguments for ILogger&lt;T&gt;.
/// </summary>
internal sealed class FakeLogger : ILogger
{
    private readonly ConcurrentBag<LogEntry> _entries = new();

    public IReadOnlyCollection<LogEntry> Entries => _entries;

    public bool HasEntries => !_entries.IsEmpty;

    public bool HasLogLevel(LogLevel level)
        => _entries.Any(e => e.Level == level);

    public bool ContainsMessage(string substring)
        => _entries.Any(e => e.Message.Contains(substring, StringComparison.OrdinalIgnoreCase));

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        _entries.Add(new LogEntry(logLevel, formatter(state, exception)));
    }

    internal readonly record struct LogEntry(LogLevel Level, string Message);
}

/// <summary>
/// Lightweight test logger that captures log entries for assertion.
/// Thread-safe. No external mocking framework required.
/// SEC-AUDIT: Verify that log messages never contain secret material.
/// </summary>
internal sealed class FakeLogger<T> : ILogger<T>
{
    private readonly ConcurrentBag<LogEntry> _entries = new();

    public IReadOnlyCollection<LogEntry> Entries => _entries;

    public bool HasEntries => !_entries.IsEmpty;

    public bool HasLogLevel(LogLevel level)
        => _entries.Any(e => e.Level == level);

    public bool ContainsMessage(string substring)
        => _entries.Any(e => e.Message.Contains(substring, StringComparison.OrdinalIgnoreCase));

    public int CountByLevel(LogLevel level)
        => _entries.Count(e => e.Level == level);

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        _entries.Add(new LogEntry(logLevel, formatter(state, exception)));
    }

    internal readonly record struct LogEntry(LogLevel Level, string Message);
}
