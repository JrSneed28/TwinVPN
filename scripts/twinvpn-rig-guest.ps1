<#
.SYNOPSIS
  SUPERSEDED 2026-08-30 — kept for the local-hardware path only.

  The First Implementation Wave gate no longer depends on this rig. The
  `WINDOWS-WFP-KILLSWITCH` criterion now runs on an Azure self-hosted L1
  controller that builds a DISPOSABLE nested guest per run and destroys it —
  `scripts/twinvpn-azure-l1.ps1`, driven by the `windows-killswitch` job in
  `.github/workflows/first-implementation-wave-gate.yml`.

  The difference that matters: this script's guest is RESTORED between runs from
  a golden checkpoint, and the restore is a discipline someone has to keep. The
  controller's guest is created from a differencing disk and deleted, so the
  golden image is never written to and there is nothing to keep.

  These two scripts still work and are still the fastest way to reproduce a
  Windows privileged run on a machine you own. They are no longer part of the
  gate.

  Provision the Hyper-V guest and register the GitHub Actions runner that
  carries `[self-hosted, Windows, twinvpn-vpn-lifecycle]`. Run ELEVATED INSIDE
  the guest.

.DESCRIPTION
  Every requirement below is derived from a step in
  build/ci/ci-windows.sh or build/ci/jobs/windows-privileged-lifecycle.yml.

  This machine carries NO signing material. Authenticode is ADR-0021's and
  belongs to the release pipeline; nothing the job runs reads a certificate, a
  password or a token.

  -Action verify is safe to run at any time and changes nothing.

.EXAMPLE
  .\twinvpn-rig-guest.ps1 -Action verify
  .\twinvpn-rig-guest.ps1 -Action register -RepoUrl https://github.com/OWNER/REPO -Token AAA... -RunnerAccount .\ci -RunnerPassword (Read-Host -AsSecureString)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('verify', 'register')]
    [string] $Action,

    [string]       $RepoUrl,
    [string]       $Token,
    [string]       $RunnerAccount,
    [SecureString] $RunnerPassword,
    [string]       $RunnerDir  = 'C:\actions-runner',
    [string]       $RunnerName = 'twinvpn-rig',
    [string]       $Labels     = 'self-hosted,Windows,twinvpn-vpn-lifecycle'
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated.'
    }
}

$script:Problems = @()
function Check([string] $What, [scriptblock] $Test, [string] $Fix) {
    $ok = $false
    try { $ok = [bool] (& $Test) } catch { $ok = $false }
    if ($ok) {
        Write-Host ("  OK    {0}" -f $What)
    } else {
        Write-Host ("  MISS  {0}" -f $What) -ForegroundColor Yellow
        Write-Host ("        -> {0}" -f $Fix)
        $script:Problems += $What
    }
}

function Invoke-Verify {
    Write-Host '=== what the privileged Windows job needs on this machine ==='

    Check 'Rust 1.90.0 on PATH' {
        (Get-Command rustc -ErrorAction SilentlyContinue) -and
        ((& rustc --version) -match '1\.90\.0')
    } 'Install rustup, then: rustup toolchain install 1.90.0; rustup default 1.90.0. rust-toolchain.toml pins it and wants rustfmt + clippy.'

    Check 'cargo on PATH' {
        [bool] (Get-Command cargo -ErrorAction SilentlyContinue)
    } 'Comes with rustup. It must be on the MACHINE PATH, not just yours, so a service can see it.'

    Check 'host target is x86_64-pc-windows-msvc' {
        (& rustc -vV) -match 'host:\s*x86_64-pc-windows-msvc'
    } 'Install the MSVC toolchain, not the GNU one.'

    # The job locates MSVC exactly this way -- through the installer's own
    # vswhere -- so a Visual Studio the installer does not know about will not
    # be found no matter where it sits on disk.
    Check 'MSVC build tools, discoverable via vswhere' {
        $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
        (Test-Path $vswhere) -and
        [bool] (& $vswhere -latest -products * -property installationPath)
    } 'Install Visual Studio Build Tools with the MSVC C++ workload.'

    Check 'Git for Windows (bash + cygpath)' {
        (Get-Command bash -ErrorAction SilentlyContinue) -and
        (Get-Command cygpath -ErrorAction SilentlyContinue)
    } 'Install Git for Windows. The job sets shell: bash and uses cmd //c ver, which needs MSYS path translation.'

    # Targeted, not a recursive scan of C:\ -- a full-disk walk takes minutes
    # and this runs on every -Action register.
    Check 'wintun.dll reachable' {
        $probes = @(
            'C:\Windows\System32\wintun.dll',
            (Join-Path $env:ProgramFiles 'TwinVPN\wintun.dll')
        ) + ($env:PATH -split ';' | Where-Object { $_ } | ForEach-Object { Join-Path $_ 'wintun.dll' })
        [bool] ($probes | Where-Object { Test-Path -LiteralPath $_ -ErrorAction SilentlyContinue } | Select-Object -First 1)
    } 'Put wintun.dll on PATH or beside the build. Without it the real adapter cannot be created and the run is not privileged, which is the whole point of this rig.'

    Check 'Base Filtering Engine running' {
        (Get-Service BFE -ErrorAction SilentlyContinue).Status -eq 'Running'
    } 'Start the BFE service. The job opens it for WRITE; a hosted runner cannot, which is the whole reason this rig exists.'

    # These two are the state ci-windows.sh --reset refuses to start on. They
    # are not "should be clean" -- the job exits 1 and says it was not restored.
    Check 'no leftover TwinVPNService' {
        -not (Get-Service TwinVPNService -ErrorAction SilentlyContinue)
    } 'Restore the golden checkpoint. ci-windows.sh --reset exits 1 on this: "the rig still has TwinVPNService registered".'

    Check 'no leftover TwinVPN* overlay adapter' {
        -not (Get-NetAdapter -ErrorAction SilentlyContinue |
              Where-Object { $_.Name -like 'TwinVPN*' -or $_.InterfaceAlias -like 'TwinVPN*' })
    } 'Restore the golden checkpoint. ci-windows.sh --reset exits 1 on this too.'

    Write-Host ''
    if ($script:Problems.Count -eq 0) {
        Write-Host 'All checks passed. This machine can carry the twinvpn-vpn-lifecycle label.' -ForegroundColor Green
        Write-Host 'Remember to prime the cargo cache once (cargo fetch + one full build): no job here has an actions/cache step and the 60-minute timeout assumes a warm cache.'
        return 0
    }
    Write-Host ("{0} unmet requirement(s). Fix them before registering the runner." -f $script:Problems.Count) -ForegroundColor Yellow
    return 1
}

Assert-Elevated

switch ($Action) {

    'verify' { exit (Invoke-Verify) }

    'register' {
        foreach ($p in 'RepoUrl', 'Token', 'RunnerAccount') {
            if (-not (Get-Variable $p -ValueOnly)) { throw "-$p is required for -Action register." }
        }
        if (-not $RunnerPassword) { throw '-RunnerPassword is required (pass it as a SecureString).' }

        if ((Invoke-Verify) -ne 0) {
            throw 'Refusing to register: the machine does not meet the job requirements above. A runner that takes a job it cannot run turns a missing prerequisite into a red gate row.'
        }

        $config = Join-Path $RunnerDir 'config.cmd'
        if (-not (Test-Path $config)) {
            throw @"
No runner package at $RunnerDir.
Download and extract it there first, using the commands GitHub shows under
Settings -> Actions -> Runners -> New self-hosted runner (the package URL and
hash change with each release, so they are not hardcoded here).
"@
        }

        $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RunnerPassword))
        try {
            # --ephemeral is load-bearing. The runner takes exactly ONE job and
            # then deregisters and exits, which is what gives the HOST a defined
            # moment to restore the checkpoint. Without it the runner picks up a
            # second job on a machine still carrying the first run's WFP
            # filters, and that run fails at --reset: correctly, but the error
            # reads as a rig misconfiguration rather than a missing restore.
            & $config --url $RepoUrl --token $Token `
                      --name $RunnerName --labels $Labels `
                      --ephemeral --unattended --replace `
                      --runasservice `
                      --windowslogonaccount $RunnerAccount `
                      --windowslogonpassword $plain
            if ($LASTEXITCODE -ne 0) { throw "config.cmd exited $LASTEXITCODE" }
        } finally {
            $plain = $null
            [GC]::Collect()
        }

        Write-Host ''
        Write-Host 'Runner registered. Now, on the HOST:' -ForegroundColor Green
        Write-Host '  .\twinvpn-rig-host.ps1 -Action checkpoint   # take the golden checkpoint WITH the runner installed'
        Write-Host '  .\twinvpn-rig-host.ps1 -Action watch        # restore-and-restart loop'
    }
}
