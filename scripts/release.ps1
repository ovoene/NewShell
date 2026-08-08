param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$')]
    [string] $Tag,

    [switch] $Push,
    [switch] $DryRun
)

$ErrorActionPreference = "Stop"

function Run-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Args)

    if ($DryRun) {
        Write-Host "git $($Args -join ' ')"
        return
    }

    & git @Args
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Args -join ' ') failed"
    }
}

function Run-Cargo {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]] $Args)

    if ($DryRun) {
        Write-Host "cargo $($Args -join ' ')"
        return
    }

    & cargo @Args
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($Args -join ' ') failed"
    }
}

function Run-CheckedOutput {
    param(
        [string] $Expected,
        [Parameter(ValueFromRemainingArguments = $true)][string[]] $Command
    )

    if ($DryRun) {
        Write-Host "$($Command -join ' ')"
        return
    }

    $output = (& $Command[0] @($Command | Select-Object -Skip 1)).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "$($Command -join ' ') failed"
    }
    if ($output -ne $Expected) {
        throw "Expected '$Expected' but got '$output'."
    }
}

$repoRoot = (& git rev-parse --show-toplevel).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
    throw "This script must be run inside a git repository."
}

Set-Location $repoRoot

& git diff --quiet --exit-code
if ($LASTEXITCODE -ne 0) {
    throw "Tracked files have unstaged changes. Commit or stash them before releasing."
}

& git diff --cached --quiet --exit-code
if ($LASTEXITCODE -ne 0) {
    throw "Tracked files have staged changes. Commit or stash them before releasing."
}

$existingTag = (& git tag --list $Tag)
if ($existingTag) {
    throw "Tag '$Tag' already exists."
}

$version = $Tag.Substring(1)
$cargoTomlPath = Join-Path $repoRoot "Cargo.toml"
$cargoLockPath = Join-Path $repoRoot "Cargo.lock"

$cargoToml = Get-Content -LiteralPath $cargoTomlPath -Raw
$newCargoToml = [regex]::Replace(
    $cargoToml,
    '(?ms)^(\[package\]\s+.*?^version\s*=\s*")[^"]+(")',
    "`${1}$version`${2}",
    1
)
if ($newCargoToml -eq $cargoToml) {
    throw "Could not update [package].version in Cargo.toml."
}

$cargoLock = Get-Content -LiteralPath $cargoLockPath -Raw
$newCargoLock = [regex]::Replace(
    $cargoLock,
    '(?ms)^(name\s*=\s*"newshell"\s*)(\r?\n)(version\s*=\s*")[^"]+(")',
    "`${1}`${2}`${3}$version`${4}",
    1
)
if ($newCargoLock -eq $cargoLock) {
    throw "Could not update newshell version in Cargo.lock."
}

if ($DryRun) {
    Write-Host "Would set Cargo.toml and Cargo.lock version to $version."
} else {
    Set-Content -LiteralPath $cargoTomlPath -Value $newCargoToml -NoNewline
    Set-Content -LiteralPath $cargoLockPath -Value $newCargoLock -NoNewline
}

Run-Cargo check --locked
Run-CheckedOutput "newshell $version" cargo run --locked -- --version

Run-Git add Cargo.toml Cargo.lock
Run-Git commit -m "Release $Tag"
Run-Git tag -a $Tag -m "Release $Tag"

if ($Push) {
    Run-Git push origin HEAD
    Run-Git push origin $Tag
    Write-Host "Released $Tag and pushed branch + tag."
} else {
    Write-Host "Created release commit and tag $Tag."
    Write-Host "Push with: git push origin HEAD && git push origin $Tag"
}
