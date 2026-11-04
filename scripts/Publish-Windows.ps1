[CmdletBinding()]
param(
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$Runtime = 'win-x64',
    [string]$Destination,
    [string]$DotNetPath = 'dotnet'
)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($Destination)) {
    $Destination = Join-Path $repository ('publish/MailSentry-' + $Runtime + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$package = [System.IO.Path]::GetFullPath($Destination)
$archive = $package + '.zip'
if ((Test-Path -LiteralPath $package) -or (Test-Path -LiteralPath $archive)) {
    throw 'Choose a new destination. Existing packages or deployments will not be overwritten.'
}
$project = Join-Path $repository 'src/MailSentry.Web/MailSentry.Web.csproj'
# Fail closed if current Microsoft release metadata cannot be checked. Self-contained
# applications do not receive Windows' separately installed runtime updates.
$metadata = Invoke-RestMethod 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json'
$release = $metadata.releases | Where-Object { $_.'release-version' -eq $metadata.'latest-release' } | Select-Object -First 1
$runtimeVersion = [version]$release.runtime.version
$aspNetVersion = [version]$release.'aspnetcore-runtime'.version
if ($runtimeVersion.Major -ne 10 -or $aspNetVersion.Major -ne 10 -or $metadata.'support-phase' -eq 'eol') { throw 'Unsupported or invalid runtime release metadata.' }
& $DotNetPath publish $project -c Release -r $Runtime --self-contained true -o $package "-p:RuntimeFrameworkVersion=$runtimeVersion" '-p:TargetLatestRuntimePatch=true' '-p:PublishSingleFile=false' '-p:PublishTrimmed=false' '-p:DebugType=None' '-p:DebugSymbols=false'
if ($LASTEXITCODE -ne 0) { throw 'Publish failed. No archive was created.' }
$runtimeConfig = Get-Content -Raw -LiteralPath (Join-Path $package 'MailSentry.runtimeconfig.json') | ConvertFrom-Json
foreach ($framework in @(@('Microsoft.NETCore.App', $runtimeVersion), @('Microsoft.AspNetCore.App', $aspNetVersion))) {
    $bundled = $runtimeConfig.runtimeOptions.includedFrameworks | Where-Object { $_.name -eq $framework[0] }
    if (!$bundled -or [version]$bundled.version -lt $framework[1]) {
        throw "Outdated bundled $($framework[0]) runtime. Install the latest .NET 10 SDK and publish again. No archive was created."
    }
}
# Verify publication did not bring local configuration, authentication records or operational state.
$unexpected = Get-ChildItem -LiteralPath $package -Recurse -File | Where-Object {
    ($_.Name -like 'appsettings*.json' -and $_.Name -ne 'appsettings.example.json') -or $_.Name -like 'auth-record*' -or $_.Name -like '.env*' -or $_.Name -in @('scan-state.bin', 'scan-run.bin', 'account.bin', 'catalog.bin', 'authentication-status.json', 'authentication.lock', 'scan.lock') -or $_.Extension -in @('.log', '.pfx', '.p12', '.pem', '.key', '.cache')
}
if ($unexpected) { throw 'Unexpected private configuration or state in publish output. No archive was created.' }
Copy-Item -LiteralPath (Join-Path $repository 'appsettings.example.json') -Destination (Join-Path $package 'appsettings.json')
$starter = Get-Content -Raw -LiteralPath (Join-Path $package 'appsettings.json') | ConvertFrom-Json
if ($starter.MailSentry.DryRun -ne $true -or $starter.MicrosoftGraph.ClientId -ne 'YOUR-APPLICATION-CLIENT-ID') {
    throw 'The starter configuration must use DryRun and a placeholder client ID.'
}
if (![string]::IsNullOrEmpty($starter.Admin.Password)) { throw 'The starter must not contain an admin password.' }
@{ runtime = $runtimeConfig.runtimeOptions.includedFrameworks; builtAtUtc = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $package 'release-info.json') -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $repository 'deployment/windows/Run-Web.cmd') -Destination $package
Copy-Item -LiteralPath (Join-Path $repository 'deployment/windows/Run-Scan.cmd') -Destination $package
Copy-Item -LiteralPath (Join-Path $repository 'deployment/windows/START-HERE.md') -Destination $package
Copy-Item -LiteralPath (Join-Path $repository 'README.md'), (Join-Path $repository 'LICENSE') -Destination $package
Copy-Item -LiteralPath (Join-Path $repository 'docs') -Destination $package -Recurse
foreach ($required in @('MailSentry.exe', 'coreclr.dll', 'hostfxr.dll', 'wwwroot/index.html', 'signatures/001-core.json')) {
    if (!(Test-Path -LiteralPath (Join-Path $package $required))) { throw "Missing package file: $required" }
}
# Include the containing folder so extracting creates one application directory.
Compress-Archive -LiteralPath $package -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
Set-Content -LiteralPath ($archive + '.sha256') -Value ($hash + '  ' + [System.IO.Path]::GetFileName($archive)) -Encoding ASCII
Write-Output "Package directory: $package"
Write-Output "ZIP: $archive"
Write-Output "SHA256: $hash"
