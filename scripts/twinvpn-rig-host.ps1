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

  Create and drive the Hyper-V guest that carries the `twinvpn-vpn-lifecycle`
  runner label. Run ELEVATED on the Hyper-V host.

.DESCRIPTION
  The privileged Windows lifecycle job needs a machine it may leave dirty.
  `build/ci/ci-windows.sh --cleanup` removes TwinVPNService and the overlay
  adapter and DELIBERATELY LEAVES the WFP filters, because ADR-0018 CB-6 and
  ADR-0022 §11.4 require enforcement to survive the process. `--reset` then
  refuses to start dirty:

      ::error::the rig still has TwinVPNService registered; it was not restored
      ::error::the rig still has a TwinVPN overlay adapter; it was not restored

  So run 1 passes on any Windows box and run 2 onwards fails until something
  restores the machine. This script is that something.

  Three details are load-bearing and none is obvious:

    * automatic checkpoints are DISABLED -- one taken mid-run captures exactly
      the dirty state being discarded;
    * the runner is registered `--ephemeral` (see twinvpn-rig-guest.ps1), so it
      takes one job and exits, giving this script a defined moment to restore;
    * the golden checkpoint is taken AFTER the runner is registered, so a
      restore comes back with the runner already installed.

.EXAMPLE
  .\twinvpn-rig-host.ps1 -Action create -IsoPath C:\iso\Win11_24H2.iso
  .\twinvpn-rig-host.ps1 -Action checkpoint      # after provisioning the guest
  .\twinvpn-rig-host.ps1 -Action watch           # restore-and-restart loop
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('create', 'checkpoint', 'watch', 'restore', 'status')]
    [string] $Action,

    [string] $VMName       = 'twinvpn-rig',
    [string] $VhdRoot      = 'C:\Hyper-V',
    [string] $IsoPath,
    [string] $SnapshotName = 'golden',
    [int]    $MemoryGB     = 8,
    [int]    $DiskGB       = 128,
    [int]    $Cpus         = 4,
    [int]    $PollSeconds  = 30
)

$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated. Every Hyper-V cmdlet below needs it.'
    }
}

function Assert-HyperV {
    if (-not (Get-Service -Name vmms -ErrorAction SilentlyContinue)) {
        throw 'The Hyper-V Virtual Machine Management service (vmms) is not present. Enable the Hyper-V role first.'
    }
    if ((Get-Service -Name vmms).Status -ne 'Running') {
        throw 'vmms is installed but not running. Start it, then re-run.'
    }
}

Assert-Elevated
Assert-HyperV

switch ($Action) {

    'create' {
        if (-not $IsoPath) { throw '-IsoPath is required for -Action create.' }
        if (-not (Test-Path $IsoPath)) { throw "ISO not found: $IsoPath" }
        if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
            throw "VM '$VMName' already exists. Remove it first, or pass a different -VMName."
        }

        # The VHDX wants real space. Check before creating, because Hyper-V will
        # happily create a dynamic disk that cannot grow to its stated size.
        $drive = (Split-Path -Qualifier $VhdRoot).TrimEnd(':')
        $free  = (Get-PSDrive -Name $drive).Free / 1GB
        if ($free -lt ($DiskGB * 0.5)) {
            Write-Warning ("{0}: only {1:N1} GB free for a {2} GB disk. A dynamic VHDX starts small but the guest will need the room." -f $drive, $free, $DiskGB)
        }

        New-Item -ItemType Directory -Force -Path $VhdRoot | Out-Null

        New-VM -Name $VMName -Generation 2 `
               -MemoryStartupBytes ($MemoryGB * 1GB) `
               -NewVHDPath (Join-Path $VhdRoot "$VMName.vhdx") `
               -NewVHDSizeBytes ($DiskGB * 1GB) | Out-Null

        # AutomaticCheckpointsEnabled OFF is not tidiness: an automatic
        # checkpoint taken mid-run captures the dirty state this rig exists to
        # discard, and a restore to it would start the next run already dirty.
        Set-VM -Name $VMName -ProcessorCount $Cpus -AutomaticCheckpointsEnabled $false

        Add-VMDvdDrive -VMName $VMName -Path $IsoPath
        $dvd = Get-VMDvdDrive -VMName $VMName
        Set-VMFirmware -VMName $VMName -FirstBootDevice $dvd

        Start-VM -Name $VMName
        Write-Host "Created and started '$VMName'. Install Windows, then run twinvpn-rig-guest.ps1 INSIDE the guest."
        Write-Host "When the guest is provisioned and the runner is registered, come back and run: -Action checkpoint"
    }

    'checkpoint' {
        if (Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue) {
            throw "Checkpoint '$SnapshotName' already exists. Remove it first if you mean to re-take it: Remove-VMSnapshot -VMName $VMName -Name $SnapshotName"
        }
        Checkpoint-VM -Name $VMName -SnapshotName $SnapshotName
        Write-Host "Checkpoint '$SnapshotName' taken. This is the state every run is restored to."
    }

    'restore' {
        Restore-VMCheckpoint -Name $SnapshotName -VMName $VMName -Confirm:$false
        Start-VM -Name $VMName
        Write-Host "Restored '$VMName' to '$SnapshotName' and started it."
    }

    'watch' {
        if (-not (Get-VMSnapshot -VMName $VMName -Name $SnapshotName -ErrorAction SilentlyContinue)) {
            throw "No checkpoint named '$SnapshotName'. Run -Action checkpoint first, or the loop would restore to nothing."
        }
        Write-Host "Watching '$VMName'. Restores to '$SnapshotName' whenever it stops. Ctrl+C to stop."
        Write-Host "Pair this with the 05:00 nightly in first-implementation-wave-privileged.yml: the guest must be up and registered before then."
        while ($true) {
            $vm = Get-VM -Name $VMName
            if ($vm.State -ne 'Running') {
                Write-Host ("{0}  {1} is {2}; restoring to '{3}'" -f (Get-Date -Format s), $VMName, $vm.State, $SnapshotName)
                Restore-VMCheckpoint -Name $SnapshotName -VMName $VMName -Confirm:$false
                Start-VM -Name $VMName
            }
            Start-Sleep -Seconds $PollSeconds
        }
    }

    'status' {
        Get-VM -Name $VMName | Select-Object Name, State, Uptime, AutomaticCheckpointsEnabled | Format-List
        Get-VMSnapshot -VMName $VMName | Select-Object Name, CreationTime | Format-Table -AutoSize
    }
}
