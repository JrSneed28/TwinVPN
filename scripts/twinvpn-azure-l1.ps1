<#
.SYNOPSIS
  The L1 controller for `WINDOWS-WFP-KILLSWITCH`: create a disposable nested
  Hyper-V guest, run the kill-switch sequence inside it, take the evidence out,
  destroy it.

.DESCRIPTION
  Run on the Azure Windows VM that is registered as the
  `[self-hosted, Windows, twinvpn-azure-l1]` GitHub Actions runner.

  ## Why the test cannot run on this machine

  TwinVPN's Windows kill switch installs PERSISTENT WFP filters, and ADR-0018
  CB-6 with ADR-0022 §11.4 require that "shutdown MUST NOT remove enforcement".
  A CORRECT fail-closed run therefore ends with the machine unable to reach the
  network. On the runner itself that severs the runner agent's connection to
  GitHub mid-job: the run is lost, no evidence is uploaded, and correct product
  behaviour is indistinguishable from flaky infrastructure.

  So the filters are installed in a throwaway L2 guest and this machine stays
  outside them for the whole run. Three consequences shape everything below:

    * **The channel is PowerShell Direct, not the network.** `New-PSSession
      -VMName` runs over VMBus, so it survives the guest cutting itself off. An
      SSH or WinRM session would die at exactly the moment the test starts
      working, and the failure would read as a hang.
    * **The guest is created from a DIFFERENCING disk over a golden VHDX and
      deleted afterwards.** Restoring a checkpoint would also work; creating and
      destroying is simpler and cannot leave a half-restored machine behind.
      There is no `--reset` to satisfy, because the guest never survives a run.
    * **Automatic checkpoints are off.** One taken mid-run captures precisely
      the dirty state being discarded.

  ## What this machine needs, once

    * A VM size with nested virtualization: Dv3/Ev3 or later, or any v4/v5
      series. `Get-VMHost` fails on a size without it, and this script says so
      by name rather than failing later inside `New-VM`.
    * The Hyper-V role, and an internal or external virtual switch the guest
      can use to reach the leak oracle.
    * A GOLDEN VHDX at `-GoldenVhd`: a licensed Windows install with the Rust
      toolchain, Git for Windows (this script runs bash inside the guest),
      Python 3 and the VS Build Tools, with a local administrator whose
      credentials are `-GuestCredentialPath`. The golden image is built once and
      never joined to a domain -- it is going to be cut off the network on
      purpose.

.EXAMPLE
  .\twinvpn-azure-l1.ps1 -Action run `
      -GoldenVhd C:\Hyper-V\golden\twinvpn-guest.vhdx `
      -RepoPath  $env:GITHUB_WORKSPACE `
      -EvidenceOut $env:GITHUB_WORKSPACE\build\ci\evidence
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('run', 'preflight', 'destroy')]
    [string] $Action,

    [string] $GoldenVhd,
    [string] $RepoPath,
    [string] $EvidenceOut,

    # A PSCredential exported with Export-CliXml by the machine's own account.
    # NOT a password on the command line: an argument is visible in the process
    # list to every user on the box.
    [string] $GuestCredentialPath = 'C:\Hyper-V\secrets\guest.cred.xml',

    [string] $SwitchName   = 'twinvpn-guest',
    [string] $VmRoot       = 'C:\Hyper-V\ephemeral',
    [int]    $MemoryGB     = 8,
    [int]    $Cpus         = 4,
    [int]    $BootTimeoutMinutes = 15,
    [int]    $RunTimeoutMinutes  = 60,

    # Passed into the guest. The oracle control token is a secret and is read
    # from the environment rather than from a parameter, for the same reason as
    # the credential above.
    [string] $VmName = "twinvpn-ks-$([guid]::NewGuid().ToString('N').Substring(0,8))"
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated. Every Hyper-V cmdlet below needs it.'
    }
}

function Assert-NestedVirtualization {
    # The failure this catches is a slow one otherwise: on an Azure size without
    # nested virtualization the Hyper-V role installs, `New-VM` succeeds, and the
    # guest fails to boot with a message about the hypervisor that sends people
    # looking at the golden image.
    if (-not (Get-Service -Name vmms -ErrorAction SilentlyContinue)) {
        throw @'
The Hyper-V Virtual Machine Management service is not present. This Azure VM
either lacks the Hyper-V role or is a size without nested virtualization.
Nested virtualization needs Dv3/Ev3 or later (any v4/v5 series will do); the
Av2, Dv2 and Ev2 sizes cannot host a guest at all.
'@
    }
    if ((Get-Service -Name vmms).Status -ne 'Running') {
        throw 'vmms is installed but not running. Start it, then re-run.'
    }
    if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
        throw "No virtual switch named '$SwitchName'. The guest needs one to reach the leak oracle; without egress the oracle observes nothing and the run can only be INCONCLUSIVE."
    }
}

function Assert-OracleConfigured {
    # FAIL CLOSED, HERE, BEFORE A GUEST IS BUILT. Without the oracle the guest
    # would run the whole sequence, observe nothing, and produce a report whose
    # zero observations are indistinguishable from a working kill switch.
    foreach ($name in 'TWINVPN_ORACLE_URL', 'TWINVPN_ORACLE_TOKEN') {
        if (-not [Environment]::GetEnvironmentVariable($name)) {
            throw "$name is not set. The kill-switch criterion is adjudicated by the external leak oracle; a run without one cannot produce evidence, only the appearance of it."
        }
    }
}

function Remove-Guest([string] $Name) {
    $vm = Get-VM -Name $Name -ErrorAction SilentlyContinue
    if (-not $vm) { return }
    Write-Host "destroying guest $Name"
    if ($vm.State -ne 'Off') { Stop-VM -Name $Name -TurnOff -Force }
    $disks = (Get-VMHardDiskDrive -VMName $Name).Path
    Remove-VM -Name $Name -Force
    foreach ($d in $disks) {
        if (Test-Path $d) { Remove-Item -LiteralPath $d -Force }
    }
}

Assert-Elevated

switch ($Action) {

    'preflight' {
        Assert-NestedVirtualization
        Assert-OracleConfigured
        if (-not (Test-Path $GuestCredentialPath)) {
            throw "No guest credential at $GuestCredentialPath. Create it once, as this machine's own account: Get-Credential | Export-CliXml '$GuestCredentialPath'"
        }
        if ($GoldenVhd -and -not (Test-Path $GoldenVhd)) {
            throw "No golden VHDX at $GoldenVhd."
        }
        Write-Host 'preflight: nested virtualization, switch, credential and oracle configuration are all present'
    }

    'destroy' {
        Remove-Guest $VmName
    }

    'run' {
        foreach ($p in 'GoldenVhd', 'RepoPath', 'EvidenceOut') {
            if (-not $PSBoundParameters.ContainsKey($p)) { throw "-$p is required for -Action run." }
        }
        Assert-NestedVirtualization
        Assert-OracleConfigured
        $cred = Import-CliXml -Path $GuestCredentialPath

        New-Item -ItemType Directory -Path $VmRoot -Force | Out-Null
        $diff = Join-Path $VmRoot "$VmName.vhdx"

        try {
            # A DIFFERENCING disk: the golden image is never written to, so a run
            # that corrupts the guest cannot poison the next one. This is also
            # what makes "destroy" a file delete rather than a restore.
            Write-Host "creating differencing disk over $GoldenVhd"
            New-VHD -Path $diff -ParentPath $GoldenVhd -Differencing | Out-Null

            New-VM -Name $VmName -MemoryStartupBytes ($MemoryGB * 1GB) `
                   -VHDPath $diff -Generation 2 -SwitchName $SwitchName | Out-Null
            Set-VMProcessor  -VMName $VmName -Count $Cpus
            Set-VMMemory     -VMName $VmName -DynamicMemoryEnabled $false
            # A checkpoint taken mid-run captures exactly the dirty state this
            # design exists to throw away.
            Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false `
                   -AutomaticStopAction TurnOff
            Start-VM -Name $VmName

            # PowerShell Direct over VMBus. It does not use the guest's network
            # stack, which is the whole reason the guest may cut itself off.
            Write-Host 'waiting for PowerShell Direct'
            $deadline = (Get-Date).AddMinutes($BootTimeoutMinutes)
            $session = $null
            while (-not $session -and (Get-Date) -lt $deadline) {
                $session = New-PSSession -VMName $VmName -Credential $cred -ErrorAction SilentlyContinue
                if (-not $session) { Start-Sleep -Seconds 10 }
            }
            if (-not $session) { throw "the guest never accepted a PowerShell Direct session within $BootTimeoutMinutes minutes" }

            Write-Host 'copying the tree into the guest'
            Invoke-Command -Session $session -ScriptBlock {
                if (Test-Path 'C:\twinvpn') { Remove-Item 'C:\twinvpn' -Recurse -Force }
                New-Item -ItemType Directory -Path 'C:\twinvpn' -Force | Out-Null
            }
            Copy-Item -Path (Join-Path $RepoPath '*') -Destination 'C:\twinvpn' `
                      -ToSession $session -Recurse -Force

            Write-Host 'running the kill-switch sequence inside the guest'
            $guestResult = Invoke-Command -Session $session -ArgumentList `
                @($env:TWINVPN_ORACLE_URL, $env:TWINVPN_ORACLE_TOKEN,
                  $env:GITHUB_RUN_ID, $env:GITHUB_REPOSITORY, $env:GITHUB_JOB,
                  $RunTimeoutMinutes) -ScriptBlock {
                param($OracleUrl, $OracleToken, $RunId, $Repository, $JobName, $TimeoutMinutes)
                $env:TWINVPN_ORACLE_URL        = $OracleUrl
                $env:TWINVPN_ORACLE_TOKEN      = $OracleToken
                # The mark the script refuses to run without. It is set HERE and
                # nowhere else, so the sequence cannot be started on the L1 host
                # by someone running the script by hand.
                $env:TWINVPN_DISPOSABLE_GUEST  = '1'
                $env:GITHUB_RUN_ID             = $RunId
                $env:GITHUB_REPOSITORY         = $Repository
                $env:GITHUB_JOB                = $JobName

                $bash = 'C:\Program Files\Git\bin\bash.exe'
                if (-not (Test-Path $bash)) { throw "Git for Windows is not installed in the golden image; $bash is missing" }
                $p = Start-Process -FilePath $bash -PassThru -NoNewWindow `
                     -ArgumentList '-lc', 'cd /c/twinvpn && build/ci/ci-windows-killswitch.sh'
                if (-not $p.WaitForExit($TimeoutMinutes * 60 * 1000)) {
                    $p.Kill()
                    throw "the kill-switch sequence did not finish within $TimeoutMinutes minutes"
                }
                @{ ExitCode = $p.ExitCode }
            }

            Write-Host 'copying the evidence out'
            New-Item -ItemType Directory -Path $EvidenceOut -Force | Out-Null
            # ALWAYS, even on a non-zero exit. A failing run's evidence is the
            # thing that says WHY, and a report that says NOT-EXECUTED because
            # nobody copied the file is strictly worse than one that says FAIL.
            foreach ($f in 'windows-killswitch.json', 'oracle\session.env') {
                $src = "C:\twinvpn\build\ci\evidence\$f"
                if (Invoke-Command -Session $session -ArgumentList $src -ScriptBlock { param($p) Test-Path $p }) {
                    Copy-Item -Path $src -Destination $EvidenceOut -FromSession $session -Force
                }
            }
            $logsOut = Join-Path (Split-Path $EvidenceOut -Parent) 'logs\windows'
            New-Item -ItemType Directory -Path $logsOut -Force | Out-Null
            if (Invoke-Command -Session $session -ScriptBlock { Test-Path 'C:\twinvpn\build\ci\logs\windows' }) {
                Copy-Item -Path 'C:\twinvpn\build\ci\logs\windows\*' -Destination $logsOut `
                          -FromSession $session -Recurse -Force -ErrorAction SilentlyContinue
            }

            if ($guestResult.ExitCode -ne 0) {
                throw "the kill-switch sequence failed inside the guest (exit $($guestResult.ExitCode)). The evidence and logs were still copied out; read build/ci/logs/windows/oracle-report.json for what the oracle observed."
            }
            Write-Host 'kill-switch sequence passed inside the disposable guest'
        }
        finally {
            # Step 10, on every path including a throw and a cancellation. A
            # guest left running is a guest holding a differencing disk and,
            # having installed persistent WFP filters, a machine nobody can log
            # into over the network to clean up.
            if ($session) { Remove-PSSession $session -ErrorAction SilentlyContinue }
            Remove-Guest $VmName
        }
    }
}
