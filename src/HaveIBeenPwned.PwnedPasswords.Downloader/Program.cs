using System.Buffers.Binary;
using System.Diagnostics;
using System.CommandLine;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

using Spectre.Console;

try
{
    using IHost host = CreateHostBuilder(args).Build();
    PwnedPasswordsDownloader downloader = host.Services.GetRequiredService<PwnedPasswordsDownloader>();
    RootCommand command = CreateRootCommand(downloader);
    return await command.Parse(args).InvokeAsync();
}
catch (Exception ex)
{
    ConsoleExceptionWriter.Write(ex);
    return -99;
}

static IHostBuilder CreateHostBuilder(string[] args) =>
    Host
    .CreateDefaultBuilder(args)
    .ConfigureLogging(builder => builder.ClearProviders())
    .ConfigureServices((hostContext, services) =>
    {
        services
        .AddHttpClient("PwnedPasswords")
        .UseSocketsHttpHandler((handler, provider) =>
        {
            handler.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12;
            handler.EnableMultipleHttp2Connections = true;
            handler.EnableMultipleHttp3Connections = true;
        })
        .ConfigureHttpClient(client =>
        {
            client.BaseAddress = new Uri("https://api.pwnedpasswords.com/range/");
            string? process = Environment.ProcessPath;
            if (process != null)
            {
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("hibp-downloader", FileVersionInfo.GetVersionInfo(process).ProductVersion));
            }

            client.DefaultRequestVersion = HttpVersion.Version30;
            client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            client.Timeout = TimeSpan.FromSeconds(5);
        });

        services.AddSingleton<PwnedPasswordsDownloader>();
    });

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

    RootCommand command = new("Download Pwned Passwords hash ranges for offline use.");
    command.Arguments.Add(outputFileArgument);
    command.Options.Add(parallelismOption);
    command.Options.Add(overwriteOption);
    command.Options.Add(singleFileOption);
    command.Options.Add(fetchNtlmOption);
    command.Options.Add(maxRetriesOption);
    command.SetAction(async (parseResult, cancellationToken) =>
    {
        PwnedPasswordsDownloader.Settings settings = new()
        {
            OutputFile = parseResult.GetValue(outputFileArgument) ?? "pwnedpasswords",
            Parallelism = parseResult.GetValue(parallelismOption),
            Overwrite = parseResult.GetValue(overwriteOption),
            SingleFile = parseResult.GetValue(singleFileOption),
            FetchNtlm = parseResult.GetValue(fetchNtlmOption),
            MaxRetries = parseResult.GetValue(maxRetriesOption)
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
    public long ElapsedMilliseconds;
    public double HashesPerSecond => HashesDownloaded / (ElapsedMilliseconds / 1000.0);
}

internal static class ConsoleExceptionWriter
{
    internal static void Write(Exception exception) =>
        AnsiConsole.MarkupLine($"[red]{exception.GetType().Name.EscapeMarkup()}: {exception.Message.EscapeMarkup()}[/]");
}

internal sealed class PwnedPasswordsDownloader
{
    private static readonly TimeSpan s_retryDelay = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan s_maxRetryDelay = TimeSpan.FromSeconds(10);
    private readonly Statistics _statistics = new();
    private readonly HttpClient _httpClient;

    public PwnedPasswordsDownloader(IHttpClientFactory httpClientFactory)
    {
        _httpClient = httpClientFactory.CreateClient("PwnedPasswords");
    }

    public sealed class Settings
    {
        public string OutputFile { get; init; } = "pwnedpasswords";
        public int Parallelism { get; init; }
        public bool Overwrite { get; init; }
        public bool SingleFile { get; init; }
        public bool FetchNtlm { get; init; }
        public int? MaxRetries { get; init; }
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
                MaxRetries = settings.MaxRetries
            };
        }

        using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(commandCancellationToken);
        ConsoleCancelEventHandler cancelHandler = (_, args) =>
        {
            args.Cancel = true;
            cancellationTokenSource.Cancel();
        };

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

                        if (!settings.Overwrite && Directory.EnumerateFiles(settings.OutputFile).Any())
                        {
                            AnsiConsole.MarkupLine($"Output directory {settings.OutputFile.EscapeMarkup()} already exists and is not empty. Use -o if you want to overwrite files.");
                            return;
                        }
                    }


                    var timer = Stopwatch.StartNew();
                    ProgressTask progressTask = ctx.AddTask("[green]Hash ranges downloaded[/]", true, 1024 * 1024);
                    Task processTask = ProcessRanges(settings, cancellationTokenSource.Token);

                    do
                    {
                        progressTask.Value = _statistics.HashesDownloaded;
                        ctx.Refresh();
                        await Task.Delay(100, cancellationTokenSource.Token).ConfigureAwait(false);
                    }
                    while (!processTask.IsCompleted);

                    await processTask.ConfigureAwait(false);

                    _statistics.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                    progressTask.Value = _statistics.HashesDownloaded;
                    ctx.Refresh();
                    progressTask.StopTask();
                });

            AnsiConsole.MarkupLine($"Finished downloading all hash ranges in {_statistics.ElapsedMilliseconds:N0}ms ({_statistics.HashesPerSecond:N2} hashes per second).");
            AnsiConsole.MarkupLine($"We made {_statistics.CloudflareRequests:N0} Cloudflare requests (avg response time: {(double)_statistics.CloudflareRequestTimeTotal / _statistics.CloudflareRequests:N2}ms). Of those, Cloudflare had already cached {_statistics.CloudflareHits:N0} requests, and made {_statistics.CloudflareMisses:N0} requests to the Have I Been Pwned origin server.");

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

    private async Task<HttpResponseMessage> GetPwnedPasswordsRangeFromWeb(string prefix, bool fetchNtlm, CancellationToken cancellationToken)
    {
        Stopwatch cloudflareTimer = Stopwatch.StartNew();
        string requestUri = prefix;
        if (fetchNtlm)
        {
            requestUri += "?mode=ntlm";
        }

        HttpResponseMessage response = await _httpClient.GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        Interlocked.Add(ref _statistics.CloudflareRequestTimeTotal, cloudflareTimer.ElapsedMilliseconds);
        Interlocked.Increment(ref _statistics.CloudflareRequests);

        TrackCloudflareCacheStatus(response);

        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        HttpStatusCode statusCode = response.StatusCode;
        response.Dispose();
        throw new HttpRequestException($"Response contained HTTP status code {(int)statusCode} ({statusCode}).", inner: null, statusCode);
    }

    private void TrackCloudflareCacheStatus(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("CF-Cache-Status", out IEnumerable<string>? values))
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

    private async Task ProcessRanges(Settings settings, CancellationToken cancellationToken)
    {
        if (settings.SingleFile)
        {
            Channel<Task<DownloadedRange>> downloadTasks = Channel.CreateBounded<Task<DownloadedRange>>(new BoundedChannelOptions(settings.Parallelism) { SingleReader = true, SingleWriter = true, AllowSynchronousContinuations = true });
            await using FileStream file = File.Open($"{settings.OutputFile}.txt", new FileStreamOptions { Access = FileAccess.Write, BufferSize = 32767, Mode = FileMode.Create, Options = FileOptions.Asynchronous, Share = FileShare.None });
            Task producerTask = StartDownloads(downloadTasks.Writer, settings, cancellationToken);
            await foreach (Task<DownloadedRange> item in downloadTasks.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                DownloadedRange range = await item.ConfigureAwait(false);
                await WriteRangeToSingleFile(range, file, settings.MaxRetries, cancellationToken).ConfigureAwait(false);
                Interlocked.Increment(ref _statistics.HashesDownloaded);
            }

            await producerTask.ConfigureAwait(false);
        }
        else
        {
            await Parallel.ForEachAsync(EnumerateRanges(), new ParallelOptions
            {
                MaxDegreeOfParallelism = settings.Parallelism,
                TaskScheduler = TaskScheduler.Default,
                CancellationToken = cancellationToken
            }, async (i, _) =>
            {
                await DownloadRangeToFile(i, settings.OutputFile, settings.FetchNtlm, settings.MaxRetries, cancellationToken).ConfigureAwait(false);
            });
        }
    }

    private static IEnumerable<int> EnumerateRanges()
    {
        for (int i = 0; i < 1024 * 1024; i++)
        {
            yield return i;
        }
    }

    private async Task StartDownloads(ChannelWriter<Task<DownloadedRange>> channelWriter, Settings settings, CancellationToken cancellationToken)
    {
        try
        {
            foreach (int i in EnumerateRanges())
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
        string prefix = GetHashRange(currentHash);

        return await ExecuteWithRetriesAsync(prefix, "downloading range data", maxRetries, async retryCancellationToken =>
        {
            using HttpResponseMessage response = await GetPwnedPasswordsRangeFromWeb(prefix, fetchNtlm, retryCancellationToken).ConfigureAwait(false);
            byte[] expectedContentMd5 = GetContentMd5(response);
            await using Stream stream = await response.Content.ReadAsStreamAsync(retryCancellationToken).ConfigureAwait(false);
            await using MemoryStream responseContent = new();
            await stream.CopyToAsync(responseContent, retryCancellationToken).ConfigureAwait(false);
            ValidateContentMd5(expectedContentMd5, responseContent.GetBuffer().AsSpan(0, checked((int)responseContent.Length)));

            responseContent.Position = 0;
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

    private async Task WriteRangeToSingleFile(DownloadedRange range, FileStream file, int? maxRetries, CancellationToken cancellationToken)
    {
        long startPosition = file.Position;

        await ExecuteWithRetriesAsync(range.Prefix, "writing single-file output", maxRetries, async retryCancellationToken =>
        {
            file.Position = startPosition;
            file.SetLength(startPosition);
            await file.WriteAsync(range.Content, retryCancellationToken).ConfigureAwait(false);
            await file.FlushAsync(retryCancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private async Task DownloadRangeToFile(int currentHash, string outputDirectory, bool fetchNtlm, int? maxRetries, CancellationToken cancellationToken)
    {
        string prefix = GetHashRange(currentHash);

        await ExecuteWithRetriesAsync(prefix, "downloading range file", maxRetries, async retryCancellationToken =>
        {
            using HttpResponseMessage response = await GetPwnedPasswordsRangeFromWeb(prefix, fetchNtlm, retryCancellationToken).ConfigureAwait(false);
            byte[] expectedContentMd5 = GetContentMd5(response);
            await using Stream stream = await response.Content.ReadAsStreamAsync(retryCancellationToken).ConfigureAwait(false);
            using SafeFileHandle handle = File.OpenHandle(Path.Combine(outputDirectory, $"{prefix}.txt"), FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous);
            using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.MD5);
            await handle.CopyFrom(stream, hash, cancellationToken: retryCancellationToken).ConfigureAwait(false);
            ValidateContentMd5(expectedContentMd5, hash.GetHashAndReset());
        }, cancellationToken).ConfigureAwait(false);

        Interlocked.Increment(ref _statistics.HashesDownloaded);
    }

    private static byte[] GetContentMd5(HttpResponseMessage response) =>
        response.Content.Headers.ContentMD5 ?? throw new InvalidDataException("Response did not contain a Content-MD5 header.");

    private static void ValidateContentMd5(byte[] expectedHash, ReadOnlySpan<byte> content)
    {
        byte[] actualHash = MD5.HashData(content);
        ValidateContentMd5(expectedHash, actualHash);
    }

    private static void ValidateContentMd5(byte[] expectedHash, byte[] actualHash)
    {
        if (!CryptographicOperations.FixedTimeEquals(expectedHash, actualHash))
        {
            throw new InvalidDataException("Response body did not match its Content-MD5 header.");
        }
    }

    private static TimeSpan GetRetryDelay(int retryAttempt) => TimeSpan.FromSeconds(Math.Min(retryAttempt * s_retryDelay.TotalSeconds, s_maxRetryDelay.TotalSeconds));

    private static void WriteRetryMessage(string prefix, string operation, int retryAttempt, int? maxRetries, TimeSpan delay, Exception exception)
    {
        string retryLimit = maxRetries is int boundedRetryCount ? $"/{boundedRetryCount}" : string.Empty;
        string exceptionType = exception.GetType().Name.EscapeMarkup();
        string exceptionMessage = exception.Message.EscapeMarkup();
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
        int retryAttempt = 0;

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
                TimeSpan delay = GetRetryDelay(retryAttempt);
                WriteRetryMessage(prefix, operation, retryAttempt, maxRetries, delay, exception);
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private sealed class DownloadedRange
    {
        public DownloadedRange(string prefix, byte[] content)
        {
            Prefix = prefix;
            Content = content;
        }

        public string Prefix { get; }
        public byte[] Content { get; }
    }
}
