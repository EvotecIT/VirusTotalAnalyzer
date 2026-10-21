using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalAnalyzer.Tests;

public sealed partial class VirusTotalClientBatchTests
{
    /// <summary>Advances the batch scheduler without relying on runner timer latency.</summary>
    private sealed class BatchTestClock
    {
        private readonly object _sync = new();
        private readonly SemaphoreSlim _scheduled = new(0);
        private readonly List<(long Deadline, TaskCompletionSource<bool> Completion)> _waits = new();
        private long _timestamp = Stopwatch.Frequency * 10;

        internal long GetTimestamp()
        {
            lock (_sync) return _timestamp;
        }

        internal async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync)
            {
                var ticks = (long)Math.Ceiling(delay.TotalSeconds * Stopwatch.Frequency);
                _waits.Add((_timestamp + ticks, completion));
            }
            _scheduled.Release();
            using (cancellationToken.Register(() => completion.TrySetCanceled()))
                await completion.Task.ConfigureAwait(false);
        }

        internal Task WaitForDelayAsync(CancellationToken cancellationToken)
            => _scheduled.WaitAsync(cancellationToken);

        internal long PendingDeadline
        {
            get { lock (_sync) return _waits.Single().Deadline; }
        }

        internal void Advance(TimeSpan duration)
        {
            TaskCompletionSource<bool>[] ready;
            lock (_sync)
            {
                _timestamp += (long)Math.Round(duration.TotalSeconds * Stopwatch.Frequency);
                ready = _waits.Where(wait => wait.Deadline <= _timestamp).Select(wait => wait.Completion).ToArray();
                _waits.RemoveAll(wait => wait.Deadline <= _timestamp);
            }
            foreach (var completion in ready) completion.TrySetResult(true);
        }
    }
}
