using System.Net.Http.Headers;
using System.Text;

internal sealed class RangeIndex
{
    private readonly ReaderWriterLockSlim _lock = new();
    private readonly SortedDictionary<string, string> _etags = new(StringComparer.Ordinal);

    public int Count
    {
        get
        {
            _lock.EnterReadLock();
            try
            {
                return _etags.Count;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }
    }

    public static async Task<RangeIndex> LoadAsync(string path, bool force, CancellationToken cancellationToken)
    {
        var index = new RangeIndex();
        if (force || !File.Exists(path))
        {
            return index;
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        using var reader = new StreamReader(stream);
        var lineNumber = 0;
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            lineNumber++;
            var separatorIndex = line.IndexOf('\t');
            if (separatorIndex != 5 || line.IndexOf('\t', separatorIndex + 1) >= 0)
            {
                throw new InvalidDataException($"Index file {path} contains an invalid entry on line {lineNumber}.");
            }

            var prefix = line[..separatorIndex];
            var etag = line[(separatorIndex + 1)..];
            if (!IsHashRange(prefix) || !EntityTagHeaderValue.TryParse(etag, out _))
            {
                throw new InvalidDataException($"Index file {path} contains an invalid entry on line {lineNumber}.");
            }

            if (!index.TryAdd(prefix, etag))
            {
                throw new InvalidDataException($"Index file {path} contains a duplicate prefix on line {lineNumber}.");
            }
        }

        return index;
    }

    public bool TryGet(string prefix, out string? etag)
    {
        _lock.EnterReadLock();
        try
        {
            return _etags.TryGetValue(prefix, out etag);
        }
        finally
        {
            _lock.ExitReadLock();
        }
    }

    public void Set(string prefix, string etag)
    {
        _lock.EnterWriteLock();
        try
        {
            _etags[prefix] = etag;
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public void Remove(string prefix)
    {
        _lock.EnterWriteLock();
        try
        {
            _etags.Remove(prefix);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }

    public async Task SaveAsync(string path, CancellationToken cancellationToken)
    {
        var temporaryPath = Path.Combine(Path.GetDirectoryName(path)!, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        KeyValuePair<string, string>[] entries;
        _lock.EnterReadLock();
        try
        {
            entries = _etags.ToArray();
        }
        finally
        {
            _lock.ExitReadLock();
        }

        try
        {
            await using (var stream = new FileStream(temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 32767, FileOptions.Asynchronous))
            await using (var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), leaveOpen: true))
            {
                foreach (var entry in entries)
                {
                    await writer.WriteAsync(entry.Key.AsMemory(), cancellationToken).ConfigureAwait(false);
                    await writer.WriteAsync("\t".AsMemory(), cancellationToken).ConfigureAwait(false);
                    await writer.WriteLineAsync(entry.Value.AsMemory(), cancellationToken).ConfigureAwait(false);
                }

                await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporaryPath, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static bool IsHashRange(string prefix) =>
        prefix.Length == 5 && prefix.All(static character => char.IsAsciiHexDigit(character) && !char.IsLower(character));

    private bool TryAdd(string prefix, string etag)
    {
        _lock.EnterWriteLock();
        try
        {
            return _etags.TryAdd(prefix, etag);
        }
        finally
        {
            _lock.ExitWriteLock();
        }
    }
}
