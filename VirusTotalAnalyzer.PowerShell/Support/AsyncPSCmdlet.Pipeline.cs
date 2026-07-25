using System;
using System.Collections.Concurrent;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;

using System.IO;
using System.Text;
using VirusTotalAnalyzer.Models;
namespace VirusTotalAnalyzer.PowerShell;

public abstract partial class AsyncPSCmdlet
{
    /// <summary>Thread-safe progress bridge for asynchronous cmdlet code.</summary>
    public new void WriteProgress(ProgressRecord progressRecord)
    {
        if (CanAccessPipelineDirectly && Volatile.Read(ref _currentOutPipe) is null)
        {
            ThrowIfStopped();
            base.WriteProgress(progressRecord);
            return;
        }

        if (Volatile.Read(ref _currentOutPipe) is null)
            return;

        _ = TryQueue(new PipelineItem(progressRecord, PipelineType.Progress));
    }

    /// <summary>
    /// Returns the effective <see cref="ActionPreference"/> for the current cmdlet.
    /// </summary>
    /// <returns>The user-specified or session error action preference.</returns>
    protected ActionPreference GetErrorActionPreference() {
        var preference = (ActionPreference)SessionState.PSVariable.GetValue("ErrorActionPreference");
        if (MyInvocation.BoundParameters.ContainsKey("ErrorAction")) {
            string? errorActionString = MyInvocation.BoundParameters["ErrorAction"]?.ToString();
            if (!string.IsNullOrWhiteSpace(errorActionString) && Enum.TryParse(errorActionString, true, out ActionPreference parsed)) {
                preference = parsed;
            }
        }
        return preference;
    }

    /// <summary>
    /// Verifies that the specified file exists and handles errors according to the
    /// provided <paramref name="errorAction"/>.
    /// </summary>
    /// <param name="path">Path to the file.</param>
    /// <param name="errorAction">Action preference to follow when the file does not exist.</param>
    /// <returns>True when the file exists; otherwise, false.</returns>
    protected bool EnsureFileExists(string path, ActionPreference errorAction) {
        if (File.Exists(path)) {
            return true;
        }

        string message = $"{MyInvocation.InvocationName} - The specified file does not exist: {path}";
        if (errorAction == ActionPreference.Stop) {
            var ex = new FileNotFoundException("The specified file does not exist.", path);
            ThrowTerminatingError(new ErrorRecord(ex, "FileNotFound", ErrorCategory.ObjectNotFound, path));
        } else {
            WriteWarning(message);
        }

        return false;
    }

    /// <summary>
    /// Writes a standardized API error that includes request context when available.
    /// </summary>
    /// <param name="exception">The API exception to report.</param>
    /// <param name="targetObject">Optional target associated with the failure.</param>
    protected void WriteApiError(ApiException exception, object? targetObject = null) {
        if (exception == null) {
            throw new ArgumentNullException(nameof(exception));
        }

        var errorId = exception.Error?.Code ?? "VirusTotalApiError";
        var record = new ErrorRecord(exception, errorId, ErrorCategory.InvalidOperation, targetObject);

        var details = new StringBuilder();
        if (exception.StatusCode.HasValue) {
            details.Append($"StatusCode: {(int)exception.StatusCode.Value} ({exception.StatusCode})");
        }
        if (!string.IsNullOrWhiteSpace(exception.RequestId)) {
            if (details.Length > 0) {
                details.AppendLine();
            }
            details.Append($"RequestId: {exception.RequestId}");
        }
        if (details.Length > 0) {
            record.ErrorDetails = new ErrorDetails(details.ToString());
        }

        WriteError(record);
    }

    /// <summary>Throws when PowerShell has requested cancellation.</summary>
    protected internal void ThrowIfStopped()
    {
        if (_cancelSource.IsCancellationRequested)
            throw new PipelineStoppedException();
    }

    /// <inheritdoc />
    public virtual void Dispose()
    {
        lock (_lifecycleLock)
        {
            if (_disposeRequested)
                return;

            _disposeRequested = true;
        }

        CancelSource();

        lock (_lifecycleLock)
        {
            DisposeCancelSourceIfInactive();
        }

        _pipelineThreadId = 0;
    }

    private bool IsPipelineThread
        => _pipelineThreadId != 0 && Environment.CurrentManagedThreadId == _pipelineThreadId;

    private bool CanAccessPipelineDirectly
        => IsPipelineThread || Volatile.Read(ref _asyncLifecycleStarted) == 0;

    private void GetBlockTaskResult(Task blockTask)
    {
        try
        {
            blockTask.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException) when (_cancelSource.IsCancellationRequested)
        {
            throw new PipelineStoppedException();
        }
    }

    private object? RequestPipelineReply(object? value, PipelineType type)
    {
        ThrowIfStopped();
        var replyPipe = new PipelineReplyChannel();
        if (!TryQueue(new PipelineItem(value, type, replyPipe)))
        {
            replyPipe.Abandon();
            ThrowIfStopped();
            throw new InvalidOperationException("No active PowerShell pipeline is available for the asynchronous request.");
        }

        try
        {
            return replyPipe.Take(CancelToken).Value;
        }
        finally
        {
            replyPipe.ReleaseRequester();
        }
    }

    private bool TryQueue(PipelineItem item)
    {
        var outPipe = Volatile.Read(ref _currentOutPipe);
        if (outPipe is null)
            return false;

        try
        {
            outPipe.Add(item, CancelToken);
            return true;
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (OperationCanceledException) when (_cancelSource.IsCancellationRequested)
        {
            return false;
        }
    }

    private void RunBlockInAsync(Func<Task> task)
    {
        EnterAsyncBlock();
        try
        {
            RunBlockInAsyncCore(task);
        }
        finally
        {
            ExitAsyncBlock();
        }
    }

    private void RunBlockInAsyncCore(Func<Task> task)
    {
        var outPipe = new BlockingCollection<PipelineItem>();
        Task blockTask;
        var deferPipeDisposal = 0;
        var pipeDisposed = 0;

        void ClearPipes()
        {
            _ = Interlocked.CompareExchange(ref _currentOutPipe, null, outPipe);
            CompleteAddingIfNeeded(outPipe);
        }

        void DisposePipeOnce()
        {
            if (Interlocked.Exchange(ref pipeDisposed, 1) == 0)
                outPipe.Dispose();
        }

        static void CompleteAddingIfNeeded<T>(BlockingCollection<T> pipe)
        {
            try
            {
                if (!pipe.IsAddingCompleted)
                    pipe.CompleteAdding();
            }
            catch (ObjectDisposedException)
            {
                // A deferred worker may race the one-time disposal after a pipeline failure.
            }
        }

        void PumpItem(PipelineItem item)
        {
            switch (item.Type)
            {
                case PipelineType.Output:
                    base.WriteObject(item.Value);
                    break;
                case PipelineType.OutputEnumerate:
                    base.WriteObject(item.Value, enumerateCollection: true);
                    break;
                case PipelineType.Error:
                    base.WriteError((ErrorRecord)item.Value!);
                    break;
                case PipelineType.TerminatingError:
                    base.ThrowTerminatingError((ErrorRecord)item.Value!);
                    break;
                case PipelineType.Warning:
                    base.WriteWarning((string)item.Value!);
                    break;
                case PipelineType.Verbose:
                    base.WriteVerbose((string)item.Value!);
                    break;
                case PipelineType.Debug:
                    base.WriteDebug((string)item.Value!);
                    break;
                case PipelineType.Information:
                    base.WriteInformation((InformationRecord)item.Value!);
                    break;
                case PipelineType.InformationWithTags:
                    var information = ((object MessageData, string[] Tags))item.Value!;
                    base.WriteInformation(information.MessageData, information.Tags);
                    break;
                case PipelineType.Progress:
                    base.WriteProgress((ProgressRecord)item.Value!);
                    break;
                case PipelineType.ShouldProcessTarget:
                    item.ReplyPipe!.Publish(
                        () => base.ShouldProcess((string)item.Value!));
                    break;
                case PipelineType.ShouldProcess:
                    var should = ((string Target, string Action))item.Value!;
                    item.ReplyPipe!.Publish(
                        () => base.ShouldProcess(should.Target, should.Action));
                    break;
                case PipelineType.ShouldProcessVerbose:
                    var verbose = ((string Description, string Warning, string Caption))item.Value!;
                    item.ReplyPipe!.Publish(
                        () => base.ShouldProcess(verbose.Description, verbose.Warning, verbose.Caption));
                    break;
                case PipelineType.ShouldProcessReason:
                    var reasonRequest = ((string Description, string Warning, string Caption))item.Value!;
                    item.ReplyPipe!.Publish(() =>
                    {
                        var result = base.ShouldProcess(
                            reasonRequest.Description,
                            reasonRequest.Warning,
                            reasonRequest.Caption,
                            out var reason);
                        return (result, reason);
                    });
                    break;
                case PipelineType.ShouldContinue:
                    var shouldContinue = ((string Query, string Caption))item.Value!;
                    item.ReplyPipe!.Publish(
                        () => base.ShouldContinue(shouldContinue.Query, shouldContinue.Caption));
                    break;
                case PipelineType.ShouldContinueAll:
                    var shouldContinueAll =
                        ((string Query, string Caption, bool YesToAll, bool NoToAll))item.Value!;
                    item.ReplyPipe!.Publish(() =>
                    {
                        var yesToAll = shouldContinueAll.YesToAll;
                        var noToAll = shouldContinueAll.NoToAll;
                        var continueAll = base.ShouldContinue(
                            shouldContinueAll.Query,
                            shouldContinueAll.Caption,
                            ref yesToAll,
                            ref noToAll);
                        return (continueAll, yesToAll, noToAll);
                    });
                    break;
                case PipelineType.ShouldContinueSecurity:
                    var shouldContinueSecurity =
                        ((string Query, string Caption, bool HasSecurityImpact, bool YesToAll, bool NoToAll))item.Value!;
                    item.ReplyPipe!.Publish(() =>
                    {
                        var yesToAll = shouldContinueSecurity.YesToAll;
                        var noToAll = shouldContinueSecurity.NoToAll;
                        var continueSecurity = base.ShouldContinue(
                            shouldContinueSecurity.Query,
                            shouldContinueSecurity.Caption,
                            shouldContinueSecurity.HasSecurityImpact,
                            ref yesToAll,
                            ref noToAll);
                        return (continueSecurity, yesToAll, noToAll);
                    });
                    break;
                case PipelineType.PromptForCredential:
                    var prompt = ((string Caption, string Message, string UserName, string TargetName))item.Value!;
                    item.ReplyPipe!.Publish(
                        () => Host.UI.PromptForCredential(
                            prompt.Caption,
                            prompt.Message,
                            prompt.UserName,
                            prompt.TargetName));
                    break;
            }
        }

        void PumpQueuedItems()
        {
            while (outPipe.TryTake(out var item))
                PumpItem(item);
        }

        Volatile.Write(ref _asyncLifecycleStarted, 1);
        _pipelineThreadId = Environment.CurrentManagedThreadId;
        Volatile.Write(ref _currentOutPipe, outPipe);

        var synchronizationContext = SynchronizationContext.Current;
        try
        {
            SynchronizationContext.SetSynchronizationContext(HookSynchronizationContext);
            if (TaskScheduler.Current == TaskScheduler.Default)
            {
                blockTask = task();
            }
            else
            {
                var invocationTask = new Task<Task>(
                    task,
                    CancellationToken.None,
                    TaskCreationOptions.DenyChildAttach);
                invocationTask.RunSynchronously(HookTaskScheduler);
                blockTask = invocationTask.GetAwaiter().GetResult();
            }
        }
        catch (Exception exception)
        {
            ClearPipes();
            DisposePipeOnce();

            if (exception is OperationCanceledException && _cancelSource.IsCancellationRequested)
                throw new PipelineStoppedException();

            throw;
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(synchronizationContext);
        }

        if (blockTask.IsCompleted)
        {
            CompleteAddingIfNeeded(outPipe);
            try
            {
                PumpQueuedItems();
            }
            finally
            {
                ClearPipes();
                DisposePipeOnce();
            }

            GetBlockTaskResult(blockTask);
            return;
        }

        RetainAsyncBlock();
        try
        {
            _ = blockTask.ContinueWith(
                completed =>
                {
                    try
                    {
                        if (completed.IsFaulted)
                            _ = completed.Exception;

                        ClearPipes();
                        if (Volatile.Read(ref deferPipeDisposal) != 0)
                            DisposePipeOnce();
                    }
                    finally
                    {
                        ExitAsyncBlock();
                    }
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }
        catch
        {
            ExitAsyncBlock();
            throw;
        }

        try
        {
            foreach (var item in outPipe.GetConsumingEnumerable(CancelToken))
            {
                PumpItem(item);
            }
        }
        catch (Exception pipelineException)
        {
            var stopRequested = _cancelSource.IsCancellationRequested;
            Volatile.Write(ref deferPipeDisposal, 1);
            CancelSource();
            CompleteAddingIfNeeded(outPipe);
            if (blockTask.IsCompleted)
                DisposePipeOnce();

            if (pipelineException is OperationCanceledException && stopRequested)
                throw new PipelineStoppedException();

            throw;
        }

        try
        {
            GetBlockTaskResult(blockTask);
        }
        finally
        {
            DisposePipeOnce();
        }
    }

    private void EnterAsyncBlock()
    {
        lock (_lifecycleLock)
        {
            if (_disposeRequested)
                throw new ObjectDisposedException(GetType().FullName);

            _activeBlocks++;
        }
    }

    private void ExitAsyncBlock()
    {
        lock (_lifecycleLock)
        {
            _activeBlocks--;
            DisposeCancelSourceIfInactive();
        }
    }

    private void RetainAsyncBlock()
    {
        lock (_lifecycleLock)
        {
            _activeBlocks++;
        }
    }

    private void CancelSource()
    {
        try
        {
            _cancelSource.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Disposal may race a late StopProcessing callback after all async hooks have exited.
        }
    }

    private void DisposeCancelSourceIfInactive()
    {
        if (!_disposeRequested || _activeBlocks != 0 || _cancelSourceDisposed)
            return;

        _cancelSource.Dispose();
        _cancelSourceDisposed = true;
    }
}
