<#
.SYNOPSIS
  Build the disposable guest's BASE VHDX from a pinned Microsoft evaluation ISO,
  using only in-box Windows tooling.

.DESCRIPTION
  Called by `scripts/twinvpn-l1.ps1 -Action build-image`. It replaces the golden
  VHDX the lane used to require from a self-hosted host: there is no image to
  keep, no image to go stale, and no repository variable naming one.

  ## Why the image is applied rather than installed

  Windows Setup is not run. `Expand-WindowsImage` applies `install.wim`
  straight into a partitioned VHDX and `bcdboot` writes the UEFI boot files,
  which skips the entire Setup pass. First boot then runs specialize and
  oobeSystem, and the unattend file the CALLER injects into the per-run
  differencing disk answers those.

  ## Why the digest is not optional

  The ISO is fetched over a plain CDN URL. Without the pinned SHA-256 the
  device under test is whatever the network handed us, and every claim the
  criterion makes would be about an image nobody can name. The URL, the size
  and the sum are pinned exactly as `dockur/windows` `src/define.sh` pins them.

  ## What is deliberately NOT installed in the image

  No Rust toolchain, no MSVC, no package manager, no Python. The binaries under
  test are built on L1 and copied in, digested on both sides of the copy. A
  guest carrying a compiler and a package cache is not a machine that resembles
  a user's, and the evidence would be about the wrong host.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VhdPath,
    [Parameter(Mandatory)] [string] $WorkDir,
    [string] $SystemLetter  = 'S',
    [string] $WindowsLetter = 'W',
    [int]    $SizeGB        = 40,
    # Start the ISO download in the background and return. The job builds its
    # Rust binaries while the 4.8 GB transfer runs (run 11 measured 7m38s for
    # it, serial, before any build could start); the normal invocation then
    # waits for that download instead of starting its own.
    [switch] $Prefetch
)

$ErrorActionPreference = 'Stop'

# Windows 11 Enterprise LTSC 2024 Evaluation, en-us, x64.
#
# LTSC because a Long-Term Servicing Channel build does not move underneath the
# criterion, and the client SKU because that is what the product ships to. The
# evaluation licence runs 180 days and wants activation within 10; a guest that
# is destroyed within the hour reaches neither, and a fresh guest per run
# restarts the clock, so `slmgr /rearm` never enters the picture.
#
# Pinned from dockur/windows src/define.sh, read 2026-09-02.
$IsoUrl    = 'https://software-static.download.prss.microsoft.com/dbazure/888969d5-f34g-4e03-ac9d-1f9786c66749/26100.1742.240906-0331.ge_release_svc_refresh_CLIENT_LTSC_EVAL_x64FRE_en-us.iso'
$IsoSha256 = '67cec5865eaa037a72ddc633a717a10a2bed50778862267223ddb9c60ef5da68'
$IsoBytes  = 5112850432

function Assert-Space([string] $Drive, [int] $NeedGB) {
    $free = (Get-PSDrive -Name $Drive).Free
    if ($free -lt ($NeedGB * 1GB)) {
        throw ("$Drive`: has $([math]::Round($free / 1GB, 1)) GB free and this " +
               "needs $NeedGB GB (a $([math]::Round($IsoBytes / 1GB, 1)) GB ISO " +
               "plus the applied image). Measure before building, so a run that " +
               "cannot fit says so now rather than half way through DISM.")
    }
}

$IsoPart = $null   # set below, once $WorkDir is known
$IsoPid  = $null

function Start-IsoPrefetch([string] $Path) {
    if (Test-Path $Path) { Write-Host "the ISO is already at $Path; nothing to prefetch"; return }
    if (Test-Path $IsoPid) { Write-Host "a prefetch is already running (pid $(Get-Content $IsoPid))"; return }
    Remove-Item -LiteralPath $IsoPart -Force -ErrorAction SilentlyContinue
    Write-Host "prefetching the evaluation ISO ($([math]::Round($IsoBytes / 1GB, 1)) GB) in the background"
    $p = Start-Process -FilePath 'curl.exe' -PassThru -WindowStyle Hidden `
         -ArgumentList @('-sS', '--fail', '--location', '--retry', '3', '--retry-delay', '10', '-o', $IsoPart, $IsoUrl)
    $p.Id | Set-Content -LiteralPath $IsoPid -NoNewline
}

function Get-PinnedIso([string] $Path) {
    if (Test-Path $Path) {
        Write-Host "reusing the ISO already at $Path"
    } elseif (Test-Path $IsoPid) {
        $id = [int](Get-Content -LiteralPath $IsoPid)
        Write-Host "waiting for the prefetched ISO download (pid $id)"
        $proc = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($proc) { $proc.WaitForExit() }
        Remove-Item -LiteralPath $IsoPid -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $IsoPart) -or (Get-Item $IsoPart).Length -ne $IsoBytes) {
            throw ("the prefetched ISO download did not complete: expected $IsoBytes bytes at $IsoPart, " +
                   "found $(if (Test-Path $IsoPart) { (Get-Item $IsoPart).Length } else { 'no file' })")
        }
        Move-Item -LiteralPath $IsoPart -Destination $Path -Force
    } else {
        Write-Host "downloading the evaluation ISO ($([math]::Round($IsoBytes / 1GB, 1)) GB)"
        # `curl.exe` is in-box since Windows 10 1803 and streams to disk;
        # Invoke-WebRequest buffers and is unusable at this size. Its stderr is
        # not an exception -- the exit code is what says whether it worked, and
        # under `Stop` a progress or diagnostic line would terminate the step
        # before the check below could name the failure.
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { & curl.exe -sS --fail --location --retry 3 --retry-delay 10 -o $Path $IsoUrl 2>&1 | Write-Host }
        finally { $ErrorActionPreference = $previous }
        if ($LASTEXITCODE -ne 0) { throw "the ISO download failed (curl exit $LASTEXITCODE)" }
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower()
    if ($actual -ne $IsoSha256) {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw ("the ISO does not match its pinned SHA-256. expected $IsoSha256, " +
               "downloaded $actual. This is either a different image than the one " +
               "the criterion was pinned to or a truncated transfer; either way " +
               "the run must not proceed to test bytes nobody named.")
    }
    Write-Host "ISO verified against its pinned SHA-256 ($actual)"
}

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$IsoPart = Join-Path $WorkDir 'win11-ltsc-eval.iso.part'
$IsoPid  = Join-Path $WorkDir 'iso-download.pid'
if ($Prefetch) {
    Assert-Space ((Split-Path -Qualifier $WorkDir).TrimEnd(':')) 25
    Start-IsoPrefetch (Join-Path $WorkDir 'win11-ltsc-eval.iso')
    return
}
# MEASURED, not the disk's nominal size: run 4 applied the image at 18.3 GB
# beside the 4.8 GB ISO, and the ISO is removed once applied, so the peak is
# about 23 GB plus the guest's differencing disk. The dynamic VHDX's 40 GB
# ceiling is never reached.
Assert-Space ((Split-Path -Qualifier $WorkDir).TrimEnd(':')) 25

$iso = Join-Path $WorkDir 'win11-ltsc-eval.iso'
Get-PinnedIso $iso

$mounted = $null
$vhdMounted = $false
try {
    $mounted = Mount-DiskImage -ImagePath $iso -PassThru
    $isoLetter = ($mounted | Get-Volume).DriveLetter
    $wim = "$($isoLetter):\sources\install.wim"
    if (-not (Test-Path $wim)) {
        $esd = "$($isoLetter):\sources\install.esd"
        if (-not (Test-Path $esd)) {
            throw "neither sources\install.wim nor sources\install.esd is on the mounted ISO"
        }
        $wim = $esd
    }
    # LOGGED, not asserted. The editions in an evaluation ISO are a fact about
    # Microsoft's media; index 1 is what is applied, and its name reaches the
    # job log so a reader can see which SKU the evidence is about.
    Get-WindowsImage -ImagePath $wim | Format-Table ImageIndex, ImageName, ImageSize | Out-String | Write-Host

    if (Test-Path $VhdPath) { Remove-Item -LiteralPath $VhdPath -Force }
    New-VHD -Path $VhdPath -SizeBytes ($SizeGB * 1GB) -Dynamic | Out-Null
    $disk = Mount-VHD -Path $VhdPath -Passthru | Initialize-Disk -PartitionStyle GPT -PassThru
    $vhdMounted = $true

    # GPT: EFI system partition, Microsoft Reserved, Windows. The GUIDs are the
    # documented types; `-GptType` rather than `-IsActive`, which is an MBR
    # concept and does not apply to a Generation 2 guest.
    $sys = New-Partition -DiskNumber $disk.Number -Size 100MB `
             -GptType '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    Format-Volume -Partition $sys -FileSystem FAT32 -NewFileSystemLabel 'System' -Confirm:$false | Out-Null
    Set-Partition -InputObject $sys -NewDriveLetter $SystemLetter
    New-Partition -DiskNumber $disk.Number -Size 16MB `
             -GptType '{e3c9e316-0b5c-4db8-817d-f92df00215ae}' | Out-Null
    $win = New-Partition -DiskNumber $disk.Number -UseMaximumSize `
             -GptType '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}'
    Format-Volume -Partition $win -FileSystem NTFS -NewFileSystemLabel 'Windows' -Confirm:$false | Out-Null
    Set-Partition -InputObject $win -NewDriveLetter $WindowsLetter

    Write-Host "applying the image to $($WindowsLetter):\"
    Expand-WindowsImage -ImagePath $wim -Index 1 -ApplyPath "$($WindowsLetter):\" | Out-Null
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & bcdboot "$($WindowsLetter):\Windows" /s "$($SystemLetter):" /f UEFI 2>&1 | Write-Host }
    finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "bcdboot exited $LASTEXITCODE; the guest would not boot" }
    Write-Host "base image built at $VhdPath"
}
finally {
    if ($vhdMounted) { Dismount-VHD -Path $VhdPath -ErrorAction SilentlyContinue }
    if ($mounted)    { Dismount-DiskImage -ImagePath $iso -ErrorAction SilentlyContinue }
    # The ISO is 5 GB and its job is done. A hosted runner measured 34.5 GB free
    # on C:, and the applied image plus a differencing disk needs most of it.
    Remove-Item -LiteralPath $iso -Force -ErrorAction SilentlyContinue
}
