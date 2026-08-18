# What is haveibeenpwned-downloader?
`haveibeenpwned-downloader` is a [dotnet tool](https://docs.microsoft.com/en-us/dotnet/core/tools/global-tools) to download all Pwned Passwords hash ranges and save them offline so they can be used without a dependency on the k-anonymity API.

An alternative to running this tool is to use Zsolt Müller's cURL approach in https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/issues/79 that makes use of a glob pattern and parallelism.

# Installation

## Prerequisites
Install the [.NET 10 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) or later to install the tool. Native AOT, self-contained packages are available for Windows x64, Linux x64, and macOS Apple silicon; the installed tool does not require a separate .NET runtime. Other runtime combinations use a framework-dependent fallback package and require the .NET 10 runtime.

## How to install
1. Open a command line window
2. Run `dotnet tool install --global haveibeenpwned-downloader`

## How to update to the latest version
1. Open a command line window
2. Run `dotnet tool update --global haveibeenpwned-downloader`

### Troubleshooting
If the installer is unable to resolve the package, then you can run the following and then try again.
```
dotnet nuget add source https://api.nuget.org/v3/index.json -n nuget.org
```

# Usage Examples

## **Windows**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt`
`haveibeenpwned-downloader.exe pwnedpasswords --single`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`
`haveibeenpwned-downloader.exe hashes`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt`
`haveibeenpwned-downloader.exe -n pwnedpasswords_ntlm --single`



## **Linux**


### Download all SHA1 hashes to a single txt file called `pwnedpasswords.txt` :
`haveibeenpwned-downloader pwnedpasswords --single`

### Download all SHA1 hashes to individual txt files into a custom directory called `hashes`:
`haveibeenpwned-downloader hashes`

### Download all NTLM hashes to a single txt file called `pwnedpasswords_ntlm.txt` : 
`haveibeenpwned-downloader -n pwnedpasswords_ntlm --single`



# Additional parameters

| Parameter   | Default value | Description |
|-------------|---------------|-------------|
| -s/--single | false | When set, downloads hashes to a single file instead of individual .txt files in a directory |
| -p/--parallelism | Same as `Environment.ProcessorCount` | Determines how many hashes to download at a time |
| --max-retries | Unlimited | Determines how many times each prefix is retried after a failure. Omit for unlimited retries, or pass `0` to disable retries. Retry delays increase per prefix up to 10 seconds. |
| -o/--overwrite | false | Determines if output files should be overwritten or not |
| -n | (none) | When set, the downloader fetches NTLM hashes instead of SHA1 |

# Additional usage examples
## Download all hashes to individual txt files into a custom directory called `hashes` using 64 threads to download the hashes
`haveibeenpwned-downloader.exe hashes -p 64`
## Download all hashes to a single txt file called `pwnedpasswords.txt` using 64 threads, overwriting the file if it already exists
`haveibeenpwned-downloader.exe pwnedpasswords --single -o -p 64`
## Download all hashes with at most 5 retries per prefix
`haveibeenpwned-downloader.exe pwnedpasswords --max-retries 5`
