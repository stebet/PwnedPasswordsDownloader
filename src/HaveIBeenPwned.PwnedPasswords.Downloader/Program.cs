using System.Buffers.Binary;
using System.CommandLine;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Spectre.Console;

try
{
    using var httpClient = CreateHttpClient();
    PwnedPasswordsDownloader downloader = new(httpClient);
    var command = CreateRootCommand(downloader);
    if (args.Length == 0)
    {
        args = ["--help"];
    }

    return await command.Parse(args).InvokeAsync();
}
catch (Exception ex)
{
    ConsoleExceptionWriter.Write(ex);
    return -99;
}

static HttpClient CreateHttpClient()
{
    SocketsHttpHandler handler = new()
    {
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        EnableMultipleHttp2Connections = true,
        EnableMultipleHttp3Connections = true
    };
    handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12;

    HttpClient client = new(handler)
    {
        BaseAddress = new Uri("https://api.pwnedpasswords.com/range/"),
        DefaultRequestVersion = HttpVersion.Version30,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        Timeout = TimeSpan.FromSeconds(5)
    };

    var process = Environment.ProcessPath;
    if (process != null)
    {
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-downloader", FileVersionInfo.GetVersionInfo(process).ProductVersion));
    }

    return client;
}

static RootCommand CreateRootCommand(PwnedPasswordsDownloader downloader)
{
    Argument<string> outputFileArgument = new("outputFile")
    {
        Description = "Name of the output. Defaults to pwnedpasswords, which writes hash ranges to a directory called pwnedpasswords. Use --single to write pwnedpasswords.txt instead.",
        DefaultValueFactory = _ => "pwnedpasswords"
    };
    Option<int> parallelismOption = new("--parallelism", "-p")
    {
        Description = "The number of parallel requests to make to Have I Been Pwned to download the hash ranges. If omitted or less than 2, defaults to eight times the number of processors on the machine.",
        DefaultValueFactory = _ => 0
    };
    Option<bool> overwriteOption = new("--overwrite", "-o")
    {
        Description = "Overwrite existing files while writing the results."
    };
    Option<bool> singleFileOption = new("--single", "-s")
    {
        Description = "Write the hash ranges into a single .txt file instead of individual files in a directory."
    };
    Option<bool> fetchNtlmOption = new("--ntlm", "-n")
    {
        Description = "Fetch NTLM hashes instead of SHA1."
    };
    Option<int?> maxRetriesOption = new("--max-retries")
    {
        Description = "Maximum number of retries per prefix. Omit for unlimited retries. Use 0 to disable retries."
    };
    Option<bool> forceOption = new("--force")
    {
        Description = "Ignore saved ETags, download every range, and rebuild the index for directory output."
    };

    RootCommand command = new(
        """
        Download Pwned Passwords hash ranges for offline use.

        Examples:
          Download SHA1 hash ranges to individual files in the sha1-ranges directory:
          haveibeenpwned-downloader sha1-ranges

          Download full SHA1 hashes to sha1-hashes.txt:
          haveibeenpwned-downloader sha1-hashes --single

          Download NTLM hash ranges to individual files in the ntlm-ranges directory:
          haveibeenpwned-downloader ntlm-ranges --ntlm

          Download full NTLM hashes to ntlm-hashes.txt:
          haveibeenpwned-downloader ntlm-hashes --ntlm --single
        """);
    command.Arguments.Add(outputFileArgument);
    command.Options.Add(parallelismOption);
    command.Options.Add(overwriteOption);
    command.Options.Add(singleFileOption);
    command.Options.Add(fetchNtlmOption);
    command.Options.Add(maxRetriesOption);
    command.Options.Add(forceOption);
    command.SetAction(async (parseResult, cancellationToken) =>
    {
        PwnedPasswordsDownloader.Settings settings = new()
        {
            OutputFile = parseResult.GetValue(outputFileArgument) ?? "pwnedpasswords",
            Parallelism = parseResult.GetValue(parallelismOption),
            Overwrite = parseResult.GetValue(overwriteOption),
            SingleFile = parseResult.GetValue(singleFileOption),
            FetchNtlm = parseResult.GetValue(fetchNtlmOption),
            MaxRetries = parseResult.GetValue(maxRetriesOption),
            Force = parseResult.GetValue(forceOption)
        };

        if (settings.MaxRetries < 0)
        {
            AnsiConsole.MarkupLine("[red]--max-retries must be 0 or greater.[/]");
            return 1;
        }

        return await downloader.ExecuteAsync(settings, cancellationToken).ConfigureAwait(false);
    });

    return command;
}

internal sealed class Statistics
{
    public int HashesDownloaded;
    public int CloudflareRequests;
    public int CloudflareHits;
    public int CloudflareMisses;
    public long CloudflareRequestTimeTotal;
    public int ConditionalRequests;
    public int NotModifiedRanges;
    public int ModifiedRanges;
    public int IndexEntries;
    public long ElapsedMilliseconds;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

internal static class ConsoleExceptionWriter
{
    internal static void Write(Exception exception) =>
        AnsiConsole.MarkupLine($"[red]{exception.GetType().Name.EscapeMarkup()}: {exception.Message.EscapeMarkup()}[/]");
}

internal sealed class PwnedPasswordsDownloader(HttpClient httpClient)
{
    private static readonly TimeSpan _retryDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan _maxRetryDelay = TimeSpan.FromSeconds(10);
    private readonly Statistics _statistics = new();
    private readonly HttpClient _httpClient = httpClient;

    public sealed class Settings
    {
        public string OutputFile { get; init; } = "pwnedpasswords";
        public int Parallelism { get; init; }
        public bool Overwrite { get; init; }
        public bool SingleFile { get; init; }
        public bool FetchNtlm { get; init; }
        public int? MaxRetries { get; init; }
        public bool Force { get; init; }
    }

    public async Task<int> ExecuteAsync(Settings settings, CancellationToken commandCancellationToken)
    {
        if (settings.Parallelism < 2)
        {
            settings = new Settings
            {
                OutputFile = settings.OutputFile,
                Parallelism = Math.Max(Environment.ProcessorCount * 8, 2),
                Overwrite = settings.Overwrite,
                SingleFile = settings.SingleFile,
                FetchNtlm = settings.FetchNtlm,
                MaxRetries = settings.MaxRetries,
                Force = settings.Force
            };
        }

        using var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(commandCancellationToken);
        void cancelHandler(object? _, ConsoleCancelEventArgs args)
        {
            args.Cancel = true;
            cancellationTokenSource.Cancel();
        }

        Console.CancelKeyPress += cancelHandler;

        try
        {
            await AnsiConsole.Progress()
                .AutoRefresh(false) // Turn off auto refresh
                .AutoClear(false)   // Do not remove the task list when done
                .HideCompleted(false)   // Hide tasks as they are completed
                .Columns(new TaskDescriptionColumn(), new ProgressBarColumn(), new PercentageColumn(), new RemainingTimeColumn(), new SpinnerColumn())
                .StartAsync(async ctx =>
                {
                    if (settings.SingleFile)
                    {
                        if (File.Exists($"{settings.OutputFile}.txt"))
                        {
                            if (!settings.Overwrite)
                            {
                                AnsiConsole.MarkupLine($"Output file {settings.OutputFile.EscapeMarkup()}.txt already exists. Use -o if you want to overwrite it.");
                                return;
                            }

                            File.Delete($"{settings.OutputFile}.txt");
                        }
                    }
                    else
                    {
                        if (!Directory.Exists(settings.OutputFile))
                        {
                            Directory.CreateDirectory(settings.OutputFile);
                        }

                        var indexPath = GetIndexPath(settings.OutputFile, settings.FetchNtlm);
                        var indexExists = File.Exists(indexPath);
                        if (!settings.Overwrite && !settings.Force && !indexExists && Directory.EnumerateFiles(settings.OutputFile).Any())
                        {
                            AnsiConsole.MarkupLine($"Output directory {settings.OutputFile.EscapeMarkup()} already exists and is not empty. Use -o if you want to overwrite files.");
                            return;
                        }
                    }

                    RangeIndex? index = settings.SingleFile
                        ? null
                        : await RangeIndex.LoadAsync(GetIndexPath(settings.OutputFile, settings.FetchNtlm), settings.Force, cancellationTokenSource.Token).ConfigureAwait(false);
                    var timer = Stopwatch.StartNew();
                    var progressTask = ctx.AddTask("[green]Hash ranges processed[/]", true, 1024 * 1024);
                    var processTask = ProcessRanges(settings, index, cancellationTokenSource.Token);

                    do
                    {
                        progressTask.Value = _statistics.HashesDownloaded;
                        ctx.Refresh();
                        await Task.Delay(100, cancellationTokenSource.Token).ConfigureAwait(false);
                    }
                    while (!processTask.IsCompleted);

                    await processTask.ConfigureAwait(false);
                    if (index != null)
                    {
                        await index.SaveAsync(GetIndexPath(settings.OutputFile, settings.FetchNtlm), cancellationTokenSource.Token).ConfigureAwait(false);
                        _statistics.IndexEntries = index.Count;
                    }

                    _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                    progressTask.Value = _statistics.HashesDownloaded;
                    ctx.Refresh();
                    progressTask.StopTask();
                });

            AnsiConsole.MarkupLine($"Finished processing all hash ranges in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.HashesPerSecond:N2} hash ranges per second).");
            var averageCloudflareResponseTime = _statistics.CloudflareRequests == 0
                ? 0
                : (double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests;
            AnsiConsole.MarkupLine($"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {averageCloudflareResponseTime:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the Have I Been Pwned origin server.");
            if (!settings.SingleFile)
            {
                AnsiConsole.MarkupLine($"The index made {_statistics.ConditionalRequests:N0} conditional requests. {_statistics.NotModifiedRanges:N0} ranges were unchanged, {_statistics.ModifiedRanges:N0} were modified and downloaded, and the index now contains {_statistics.IndexEntries:N0} entries.");
            }

            return 0;
        }
        catch (OperationCanceledException) when (cancellationTokenSource.IsCancellationRequested)
        {
            AnsiConsole.MarkupLine("[yellow]Download canceled.[/]");
            return -2;
        }
        catch (Exception e)
        {
            AnsiConsole.MarkupLine($"Failed to download hash ranges: {e.Message}");
            ConsoleExceptionWriter.Write(e);

            return -1;
        }
        finally
        {
            Console.CancelKeyPress -= cancelHandler;
        }
    }

    private async Task<HttpResponseMessage> GetPwnedPasswordsRangeFromWeb(string prefix, bool fetchNtlm, string? etag, CancellationToken cancellationToken)
    {
        var cloudflareTimer = Stopwatch.StartNew();
        var requestUri = prefix;
        if (fetchNtlm)
        {
            requestUri += "?mode=ntlm";
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        if (etag != null)
        {
            request.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Parse(etag));
            Interlocked.Increment(ref _statistics.ConditionalRequests);
        }

        var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
        Interlocked.Increment(ref _statistics.CloudflareRequests);

        TrackCloudflareCacheStatus(response);

        if (response.StatusCode == HttpStatusCode.NotModified)
        {
            Interlocked.Increment(ref _statistics.NotModifiedRanges);
            return response;
        }

        if (response.IsSuccessStatusCode)
        {
            if (etag != null)
            {
                Interlocked.Increment(ref _statistics.ModifiedRanges);
            }

            return response;
        }

        var statusCode = response.StatusCode;
        response.Dispose();
        throw new HttpRequestException($"Response contained HTTP status code {(int)statusCode} ({statusCode}).", inner: null, statusCode);
    }

    private void TrackCloudflareCacheStatus(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("CF-Cache-Status", out var values))
        {
            return;
        }

        switch (values.FirstOrDefault())
        {
            case "HIT":
                Interlocked.Increment(ref _statistics.CloudflareHits);
                break;
            default:
                Interlocked.Increment(ref _statistics.CloudflareMisses);
                break;
        }
    }

    private static string GetHashRange(int i)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, i);
        return Convert.ToHexString(bytes)[3..];
    }

    private static string GetIndexPath(string outputDirectory, bool fetchNtlm) =>
        Path.Combine(outputDirectory, fetchNtlm ? "ntlm.index" : "sha1.index");

    private async Task ProcessRanges(Settings settings, RangeIndex? index, CancellationToken cancellationToken)
    {
        if (settings.SingleFile)
        {
            var downloadTasks = Channel.CreateBounded<Task<DownloadedRange>>(new BoundedChannelOptions(settings.Parallelism) { SingleReader = true, SingleWriter = true, AllowSynchronousContinuations = true });
            await using var file = File.Open($"{settings.OutputFile}.txt", new FileStreamOptions { Access = FileAccess.Write, BufferSize = 32767, Mode = FileMode.Create, Options = FileOptions.Asynchronous, Share = FileShare.None });
            var producerTask = StartDownloads(downloadTasks.Writer, settings, cancellationToken);
            await foreach (var item in downloadTasks.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                var range = await item.ConfigureAwait(false);
                await WriteRangeToSingleFile(range, file, settings.MaxRetries, cancellationToken).ConfigureAwait(false);
                Interlocked.Increment(ref _statistics.HashesDownloaded);
            }

            await producerTask.ConfigureAwait(false);
        }
        else
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, 1024 * 1024), new ParallelOptions
            {
                MaxDegreeOfParallelism = settings.Parallelism,
                TaskScheduler = TaskScheduler.Default,
                CancellationToken = cancellationToken
            }, async (i, _) =>
            {
                await DownloadRangeToFile(i, settings.OutputFile, settings.FetchNtlm, settings.MaxRetries, index, cancellationToken).ConfigureAwait(false);
            });
        }
    }

    private async Task StartDownloads(ChannelWriter<Task<DownloadedRange>> channelWriter, Settings settings, CancellationToken cancellationToken)
    {
        try
        {
            foreach (var i in Enumerable.Range(0, 1024 * 1024))
            {
                await channelWriter.WriteAsync(DownloadRangeToBuffer(i, settings.FetchNtlm, settings.MaxRetries, cancellationToken), cancellationToken).ConfigureAwait(false);
            }

            channelWriter.TryComplete();
        }
        catch (Exception e)
        {
            channelWriter.TryComplete(e);
        }
    }

    private async Task<DownloadedRange> DownloadRangeToBuffer(int currentHash, bool fetchNtlm, int? maxRetries, CancellationToken cancellationToken)
    {
        var prefix = GetHashRange(currentHash);

        return await ExecuteWithRetriesAsync(prefix, "downloading range data", maxRetries, async retryCancellationToken =>
        {
            using var response = await GetPwnedPasswordsRangeFromWeb(prefix, fetchNtlm, etag: null, retryCancellationToken).ConfigureAwait(false);
            var expectedContentMd5 = GetContentMd5(prefix, response);
            await using var stream = await response.Content.ReadAsStreamAsync(retryCancellationToken).ConfigureAwait(false);
            await using MemoryStream responseContent = new();
            await stream.CopyToAsync(responseContent, retryCancellationToken).ConfigureAwait(false);
            responseContent.Seek(0, SeekOrigin.Begin);
            ValidateContentMd5(expectedContentMd5, MD5.HashData(responseContent));
            responseContent.Seek(0, SeekOrigin.Begin);
            await using MemoryStream output = new();
            await using StreamWriter writer = new(output, Encoding.UTF8, leaveOpen: true);
            using StreamReader reader = new(responseContent);

            while (await reader.ReadLineAsync(retryCancellationToken).ConfigureAwait(false) is { } line)
            {
                if (line.Length == 0)
                {
                    continue;
                }

                await writer.WriteAsync(prefix.AsMemory(), retryCancellationToken).ConfigureAwait(false);
                await writer.WriteLineAsync(line.AsMemory(), retryCancellationToken).ConfigureAwait(false);
            }

            await writer.FlushAsync(retryCancellationToken).ConfigureAwait(false);
            return new DownloadedRange(prefix, output.ToArray());
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteRangeToSingleFile(DownloadedRange range, FileStream file, int? maxRetries, CancellationToken cancellationToken)
    {
        var startPosition = file.Position;

        await ExecuteWithRetriesAsync(range.Prefix, "writing single-file output", maxRetries, async retryCancellationToken =>
        {
            file.Position = startPosition;
            file.SetLength(startPosition);
            await file.WriteAsync(range.Content, retryCancellationToken).ConfigureAwait(false);
            await file.FlushAsync(retryCancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task DownloadRangeToFile(int currentHash, string outputDirectory, bool fetchNtlm, int? maxRetries, RangeIndex? index, CancellationToken cancellationToken)
    {
        var prefix = GetHashRange(currentHash);
        var outputPath = Path.Combine(outputDirectory, $"{prefix}.txt");
        var etag = index != null && File.Exists(outputPath) && index.TryGet(prefix, out var savedEtag)
            ? savedEtag
            : null;

        await ExecuteWithRetriesAsync(prefix, "downloading range file", maxRetries, async retryCancellationToken =>
        {
            using var response = await GetPwnedPasswordsRangeFromWeb(prefix, fetchNtlm, etag, retryCancellationToken).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.NotModified)
            {
                return;
            }

            var expectedContentMd5 = GetContentMd5(prefix, response);
            await using var stream = await response.Content.ReadAsStreamAsync(retryCancellationToken).ConfigureAwait(false);
            await using (var file = File.Open(outputPath, new FileStreamOptions { Mode = FileMode.Create, Access = FileAccess.ReadWrite, Share = FileShare.None, BufferSize = 32767, Options = FileOptions.Asynchronous }))
            {
                await stream.CopyToAsync(file, retryCancellationToken).ConfigureAwait(false);
                await file.FlushAsync(retryCancellationToken).ConfigureAwait(false);
                file.Seek(0, SeekOrigin.Begin);
                ValidateContentMd5(expectedContentMd5, MD5.HashData(file));
            }

            if (index != null)
            {
                var responseEtag = response.Headers.ETag?.ToString();
                if (responseEtag != null)
                {
                    index.Set(prefix, responseEtag);
                }
                else
                {
                    AnsiConsole.MarkupLine($"[yellow]Response for prefix {prefix} did not contain an ETag header. The range will not be indexed.[/]");
                    index.Remove(prefix);
                }
            }
        }, cancellationToken).ConfigureAwait(false);

        Interlocked.Increment(ref _statistics.HashesDownloaded);
    }

    private static byte[] GetContentMd5(string prefix, HttpResponseMessage response)
    {
        if (response.Content.Headers.ContentMD5 is { } contentMd5)
        {
            return contentMd5;
        }

        AnsiConsole.MarkupLine($"[yellow]Response for prefix {prefix} did not contain a Content-MD5 header. The range cannot be verified.[/]");
        throw new InvalidDataException("Response did not contain a Content-MD5 header.");
    }

    private static void ValidateContentMd5(ReadOnlySpan<byte> expectedHash, ReadOnlySpan<byte> actualHash)
    {
        if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
        {
            throw new InvalidDataException("Response body did not match its Content-MD5 header.");
        }
    }

    private static TimeSpan GetRetryDelay(int retryAttempt) => TimeSpan.FromSeconds(Math.Min(retryAttempt * _retryDelay.TotalSeconds, _maxRetryDelay.TotalSeconds));

    private static void WriteRetryMessage(string prefix, string operation, int retryAttempt, int? maxRetries, TimeSpan delay, Exception exception)
    {
        var retryLimit = maxRetries is int boundedRetryCount ? $"/{boundedRetryCount}" : string.Empty;
        var exceptionType = exception.GetType().Name.EscapeMarkup();
        var exceptionMessage = exception.Message.EscapeMarkup();
        AnsiConsole.MarkupLine($"[yellow]Retry {retryAttempt}{retryLimit} for prefix {prefix} in {delay.TotalSeconds:N0}s while {operation}. {exceptionType}: {exceptionMessage}[/]");
    }

    private static bool IsCancellation(Exception exception, CancellationToken cancellationToken) => exception is OperationCanceledException && cancellationToken.IsCancellationRequested;

    private static async Task ExecuteWithRetriesAsync(string prefix, string operation, int? maxRetries, Func<CancellationToken, Task> work, CancellationToken cancellationToken)
    {
        await ExecuteWithRetriesAsync<object?>(prefix, operation, maxRetries, async retryCancellationToken =>
        {
            await work(retryCancellationToken).ConfigureAwait(false);
            return null;
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<T> ExecuteWithRetriesAsync<T>(string prefix, string operation, int? maxRetries, Func<CancellationToken, Task<T>> work, CancellationToken cancellationToken)
    {
        var retryAttempt = 0;

        while (true)
        {
            try
            {
                return await work(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (!IsCancellation(exception, cancellationToken))
            {
                if (maxRetries is int boundedRetryCount && retryAttempt >= boundedRetryCount)
                {
                    throw;
                }

                retryAttempt++;
                var delay = GetRetryDelay(retryAttempt);
                WriteRetryMessage(prefix, operation, retryAttempt, maxRetries, delay, exception);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private sealed class DownloadedRange(string prefix, byte[] content)
    {
        public string Prefix { get; } = prefix;
        public byte[] Content { get; } = content;
    }
}
