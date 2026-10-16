using Mta.Host.Tls;

namespace Mta.Host.Tests.Acme;

/// <summary>A DNS-01 provider that keeps the records it was asked for (several values at one name, as wildcard plus base name need) and can be told to fail.</summary>
internal sealed class RecordingDnsProvider : IDnsChallengeProvider
{
    private readonly object _gate = new();
    private readonly Dictionary<string, (string Name, string Value)> _live = [];
    private int _next;

    public List<(string Name, string Value)> Created { get; } = [];

    public List<string> DeletedHandles { get; } = [];

    /// <summary>Creating the n-th record (1-based) throws this.</summary>
    public Dictionary<int, Exception> FailCreate { get; } = [];

    /// <summary>Deleting any record throws this.</summary>
    public Exception? FailDelete { get; set; }

    public ValueTask<string> CreateTxtAsync(string fqdn, string value, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            int n = ++_next;
            if (FailCreate.TryGetValue(n, out var failure))
            {
                throw failure;
            }

            string handle = "rec-" + n;
            _live[handle] = (fqdn, value);
            Created.Add((fqdn, value));
            return ValueTask.FromResult(handle);
        }
    }

    public ValueTask DeleteTxtAsync(string handle, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            DeletedHandles.Add(handle);
            if (FailDelete is not null)
            {
                throw FailDelete;
            }

            _live.Remove(handle);
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>The TXT values published at the name right now.</summary>
    public List<string> ValuesAt(string name)
    {
        lock (_gate)
        {
            return [.. _live.Values.Where(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase)).Select(r => r.Value)];
        }
    }

    public int LiveRecords
    {
        get
        {
            lock (_gate)
            {
                return _live.Count;
            }
        }
    }
}

/// <summary>The HTTP-01 side: the answers the order published, as the listener would serve them.</summary>
internal sealed class RecordingHttpPublisher : IHttpChallengePublisher
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _answers = [];

    public List<(string Certificate, string Token, string KeyAuthorization)> Published { get; } = [];

    public List<string> Removed { get; } = [];

    /// <summary>Non-null: the listener is not available and says why.</summary>
    public string? Unavailable { get; set; }

    public ValueTask<string?> WaitUntilReadyAsync(TimeSpan timeout, CancellationToken cancellationToken) => ValueTask.FromResult(Unavailable);

    public ValueTask PublishAsync(string certificateName, string token, string keyAuthorization, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _answers[token] = keyAuthorization;
            Published.Add((certificateName, token, keyAuthorization));
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask RemoveAsync(string certificateName, string token, CancellationToken cancellationToken)
    {
        lock (_gate)
        {
            _answers.Remove(token);
            Removed.Add(token);
        }

        return ValueTask.CompletedTask;
    }

    public string? AnswerFor(string token)
    {
        lock (_gate)
        {
            return _answers.GetValueOrDefault(token);
        }
    }

    public int LiveAnswers
    {
        get
        {
            lock (_gate)
            {
                return _answers.Count;
            }
        }
    }
}
