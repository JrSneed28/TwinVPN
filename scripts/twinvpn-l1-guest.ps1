<#
.SYNOPSIS
  The steps that run INSIDE the disposable nested guest.

.DESCRIPTION
  Never invoked directly. `scripts/twinvpn-l1.ps1 -Action guest-exec` runs this
  file's contents in a PowerShell Direct session with `Invoke-Command
  -FilePath`, so the file lives on L1 and executes in the guest.

  ## Why the guest holds no control credential

  A correct kill switch blocks every packet the guest originates while armed,
  and the leak oracle's control plane is reached by a packet. A guest that
  posted its own phase boundaries and attempt counts would therefore lose
  exactly the ARMED window's posts, and the oracle reads a shortfall in the
  attempt denominator as INCONCLUSIVE. So the split is:

    * L1 (the controller) opens the session, declares phases, posts the counts
      the guest measured, closes and fetches the report. It holds the token.
    * The guest runs the DATA PLANE only -- `leak-probe.sh beacon`, writing its
      per-window counts to a file the controller reads back over VMBus -- plus
      the product steps below.

  `probe_host` stays `device` because every beacon still leaves the guest. What
  moved is the bookkeeping, not the egress.

  ## Why the addresses are parameters rather than constants

  The oracle must not be on-link with the guest. TwinVPN's Windows filters
  PERMIT the on-link prefixes (class 4, `local_network_access`, whose default
  is ALLOW in all three routing modes) and PERMIT link-local (class 9), so an
  oracle on either would be reachable while armed and the SILENCE phase would
  fail for a reason that is not a leak. `Assert-OffLink` below measures that
  the guest's own routing table sends the oracle's addresses to the default
  gateway rather than on-link, before any phase runs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('stage', 'unpack-shell', 'prepare', 'preconditions', 'service-up',
                 'route-identity', 'net-up', 'beacon', 'armed-check', 'kill', 'restore')]
    [string] $Step,
    [string] $Arg1 = '',
    [string] $Arg2 = ''
)

$ErrorActionPreference = 'Stop'

$Root    = 'C:\twinvpn'
$Bin     = Join-Path $Root 'bin'
$Bash    = Join-Path $Root 'git\bin\bash.exe'
$Ctl     = Join-Path $Bin 'twinvpnctl.exe'
$Svc     = Join-Path $Bin 'twinvpnsvc.exe'
$Precond = Join-Path $Bin 'wfp_preconditions.exe'
$Counts  = Join-Path $Root 'counts.env'

# THE GUEST'S HALF OF THE ADDRESS PLAN. Switch A is the guest's own link;
# switch B carries the oracle and is reachable only through the default route.
# Four ranges are excluded by construction and the exclusion is the design:
#   * 169.254.0.0/16 and fe80::/10 -- class 9 PERMITS link-local;
#   * anything on-link with this guest -- class 4 PERMITS local network access,
#     which is ALLOW in every routing mode (wfp/mod.rs:576);
#   * 100.64.0.0/10 and fd7c:9e5d:2a10::/48 -- the Tier-1 baseline deny floor,
#     blocked in BOTH postures, so a TUNNELLED leg there could never arrive.
$GuestV4   = '10.77.0.10'; $GuestV4Len = 24; $GatewayV4 = '10.77.0.1'
$GuestV6   = 'fd77:7717:d0c::10'; $GuestV6Len = 64; $GatewayV6 = 'fd77:7717:d0c::1'
$OracleV4  = '10.78.0.1'
$OraclePort = 8080   # twinvpn-l1.ps1 binds and advertises 8080; port 80 belongs to HTTP.sys on L1
$OracleV6  = 'fd78:7717:d0c::1'
$ResolverV4 = '10.78.0.53'
$ResolverV6 = 'fd78:7717:d0c::53'

function Say([string] $Text) { Write-Output $Text }

# NATIVE COMMANDS, WHOSE STDERR IS NOT AN EXCEPTION.
#
# `$ErrorActionPreference = 'Stop'` is right for the cmdlets here -- a
# `New-NetIPAddress` that fails must stop the step rather than leave the guest
# half-configured. It is WRONG for the native commands: PowerShell turns a
# native command's stderr into an ErrorRecord, and under `Stop` that terminates
# the step. `taskkill` on a process that is already gone, `sc.exe delete` on a
# service that does not exist, and `twinvpnctl net up` printing its refusal are
# all EXPECTED here, and every one of them writes to stderr. Their exit codes
# are read explicitly instead, which is the thing that actually carries the
# outcome.
function Invoke-Native([scriptblock] $Command) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command 2>&1 | Out-String } finally { $ErrorActionPreference = $previous }
}

# One marker per transition the guest ACTUALLY observed. The lane greps these
# out and puts them in `lifecycle_transitions`, exactly as `ci-linux.sh` does --
# a hard-coded list reports the same thing whether or not anything happened.
function Transition([string] $From, [string] $To) {
    Write-Output "TWINVPN_LIFECYCLE_TRANSITION $From->$To"
}

function Get-GuestAdapter {
    $a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object ifIndex | Select-Object -First 1
    if (-not $a) { throw 'the guest has no network adapter in the Up state' }
    return $a
}

function Assert-OffLink([string] $Address, [string] $Gateway) {
    # Find-NetRoute returns TWO objects: the source NetIPAddress it selected,
    # then the NetRoute. Run 6 took the first and read an empty NextHop off an
    # address object; only the route object carries a DestinationPrefix.
    $route = Find-NetRoute -RemoteIPAddress $Address -ErrorAction SilentlyContinue |
             Where-Object { $_.PSObject.Properties['DestinationPrefix'] } |
             Select-Object -First 1
    if (-not $route) { throw "the guest has no route at all to $Address" }
    $next = $route.NextHop
    if ($next -ne $Gateway) {
        throw ("$Address resolves via next hop '$next', not via the default " +
               "gateway $Gateway. An on-link oracle is PERMITTED by the " +
               "product's class-4 local-network filter, so a SILENCE phase " +
               "against it would fail for a reason that is not a leak.")
    }
    Say "off-link confirmed: $Address via $next"
}

function Assert-Reachable([string] $Address) {
    # BEFORE any phase, and fatal. Zero arrivals because the kill switch worked
    # and zero arrivals because the oracle was never reachable are the same
    # bytes; this is what keeps them apart on the guest's side.
    $ok = Test-NetConnection -ComputerName $Address -Port $OraclePort -InformationLevel Quiet -WarningAction SilentlyContinue
    if (-not $ok) {
        # Which hop failed, before throwing: the guest's own gateway on the
        # link (L1), then the routed oracle address. Run 7 probed port 80 after
        # the oracle had moved to 8080 and could not tell the two apart.
        foreach ($hop in @($GatewayV4, $GatewayV6, $Address)) {
            $r = Test-NetConnection -ComputerName $hop -WarningAction SilentlyContinue
            Say ("hop $hop ping=" + $r.PingSucceeded)
        }
        $r = Test-NetConnection -ComputerName $Address -Port $OraclePort -WarningAction SilentlyContinue
        Say ("tcp $Address`:$OraclePort succeeded=" + $r.TcpTestSucceeded + " via " + $r.InterfaceAlias + " source " + $r.SourceAddress.IPAddress)
        throw ("the guest cannot reach the oracle's HTTP listener at $Address`:$OraclePort " +
               "before arming. Every SILENCE phase after this would be vacuous.")
    }
    Say "oracle reachable: $Address tcp/$OraclePort"
}

switch ($Step) {

    'stage' {
        # The destinations must exist before `Copy-Item -ToSession` writes into
        # them: it does not create intermediate directories, and the failure
        # reads as a missing source rather than a missing target.
        foreach ($d in @($Root, $Bin, (Join-Path $Root 'build\ci'),
                         (Join-Path $Root 'build\ci\evidence\oracle'),
                         (Join-Path $Root 'git'))) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
        Say "staged $Root"
    }

    'unpack-shell' {
        # `leak-probe.sh` is bash, and this guest has no shell of its own. The
        # controller converts the pinned Git for Windows tarball to an
        # UNCOMPRESSED tar before copying it in, so this extraction needs no
        # compression codec at all -- in-box `tar.exe` is libarchive and reads
        # plain tar by definition, which is a narrower assumption than betting
        # on which codecs that particular build was linked against.
        $tar = Join-Path $Root 'git.tar'
        if (-not (Test-Path $tar)) { throw "no shell payload at $tar" }
        $unpackDir = Join-Path $Root 'git'
        Invoke-Native { & tar.exe -x -f $tar -C $unpackDir } | Write-Output
        if ($LASTEXITCODE -ne 0) { throw "tar exited $LASTEXITCODE unpacking the shell" }
        if (-not (Test-Path $Bash)) { throw "the shell payload contains no $Bash" }
        Remove-Item -LiteralPath $tar -Force
        Say (Invoke-Native { & $Bash -lc 'echo "TWINVPN_GUEST_FACT shell=$(bash --version | head -1)"' }).Trim()
    }

    'prepare' {
        $nic = Get-GuestAdapter
        Say "guest adapter: $($nic.Name) (ifIndex $($nic.ifIndex))"
        # Static, and DHCP off: an internal Hyper-V switch has no DHCP server,
        # so an adapter left on DHCP takes an APIPA address in 169.254.0.0/16 --
        # which the kill switch PERMITS, and the whole run would then measure
        # class 9 rather than the scope deny.
        Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled -ErrorAction SilentlyContinue
        Get-NetIPAddress -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Get-NetRoute -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
            Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $GuestV4 `
            -PrefixLength $GuestV4Len -DefaultGateway $GatewayV4 | Out-Null
        New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $GuestV6 `
            -PrefixLength $GuestV6Len -DefaultGateway $GatewayV6 | Out-Null
        # The UNPROTECTED resolver, off-link like the oracle. The protected one
        # does not exist yet: nothing in the product binds a DNS listener, so
        # there is no `--resolver <addr>=twinvpn-dns:p` address to hand out.
        Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex `
            -ServerAddresses @($ResolverV4, $ResolverV6) | Out-Null
        Say ((Get-NetIPAddress -InterfaceIndex $nic.ifIndex |
              ForEach-Object { "address: $($_.IPAddress)/$($_.PrefixLength)" }) -join "`n")

        foreach ($pair in @(@($OracleV4, $GatewayV4), @($ResolverV4, $GatewayV4),
                            @($OracleV6, $GatewayV6), @($ResolverV6, $GatewayV6))) {
            Assert-OffLink $pair[0] $pair[1]
        }
        Assert-Reachable $OracleV4
        Assert-Reachable $OracleV6

        # THE PAYLOAD, RE-DIGESTED WHERE IT WILL RUN. L1 digested the same files
        # before the copy; the lane refuses a mismatch. A digest taken only on
        # the build host says nothing about what arrived over VMBus.
        foreach ($f in @($Ctl, $Svc, $Precond)) {
            if (-not (Test-Path $f)) { throw "the payload is missing $f" }
            $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash.ToLower()
            Say "TWINVPN_GUEST_DIGEST $([IO.Path]::GetFileName($f))=$h"
        }
        if (-not (Test-Path $Bash)) { throw "no bash at $Bash; the leak probe cannot run" }
        Say "TWINVPN_GUEST_FACT windows=$((Get-CimInstance Win32_OperatingSystem).Caption) $([Environment]::OSVersion.Version)"
    }

    'preconditions' {
        # The PREBUILT test binary, not `cargo test`. There is no Rust toolchain
        # in this guest by design: building here would put a compiler, a linker
        # and a package cache inside the machine under test, and the evidence
        # would be about a host that no longer resembles a user's.
        $env:TWINVPN_WINDOWS_TEST = '1'
        Invoke-Native { & $Precond --nocapture --test-threads=1 } | Write-Output
        if ($LASTEXITCODE -ne 0) { throw "the WFP precondition probe exited $LASTEXITCODE" }
    }

    'service-up' {
        # The SHIPPED service, registered the way the MSI registers it.
        Invoke-Native { & sc.exe create TwinVPNService binPath= "$Svc" start= demand } | Out-Null
        Invoke-Native { & sc.exe start TwinVPNService } | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sc.exe start TwinVPNService exited $LASTEXITCODE" }
        Transition 'SERVICE_ABSENT' 'SERVICE_RUNNING'
        $ready = $false
        foreach ($i in 1..30) {
            Invoke-Native { & $Ctl status get } | Out-Null
            if ($LASTEXITCODE -eq 0) { $ready = $true; break }
            Start-Sleep -Seconds 1
        }
        if (-not $ready) { throw 'TwinVPNService started but never bound its management endpoint' }
        Transition 'SERVICE_RUNNING' 'MANAGEMENT_READY'
        Say (Invoke-Native { & $Ctl --output json status get }).Trim()
    }

    'route-identity' {
        # MEASURED, never declared. `PATH_IDENTITY_PREREQUISITES` refuses a row
        # whose two path identities are equal, and a pair of differing constants
        # would satisfy that check while describing nothing.
        $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Sort-Object -Property RouteMetric | Select-Object -First 1
        if ($null -eq $r) { return }   # unreadable == not established
        $nic = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue
        $ip  = Get-NetIPAddress -InterfaceIndex $r.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
               Select-Object -First 1
        Say ("if{0}:{1}:{2}" -f $r.ifIndex, $nic.Name, $ip.IPAddress)
    }

    'net-up' {
        # NOT FATAL HERE. `net.up` refuses today -- the device has no overlay
        # allocation, so `enforce::arm` returns AUTH.IDENTITY_MISSING and blocks
        # the host on the way out. Aborting on that would destroy the evidence
        # that says WHY the row is red, which is the only useful thing this run
        # can currently produce. The exit code and the refusal are printed and
        # the lane records them verbatim.
        $out = Invoke-Native { & $Ctl --output json net up }
        $code = $LASTEXITCODE
        Say "TWINVPN_NET_UP_EXIT $code"
        Say "TWINVPN_NET_UP_OUTPUT_BEGIN"
        Say $out.Trim()
        Say "TWINVPN_NET_UP_OUTPUT_END"
        if ($code -eq 0) { Transition 'MANAGEMENT_READY' 'NET_UP' }
    }

    'beacon' {
        # $Arg1 seconds, $Arg2 path tag. The tag is written where leak-probe.sh
        # looks for it: the phases are separate processes, so a variable set by
        # one of them is gone by the next.
        $oracleDir = Join-Path $Root 'build\ci\evidence\oracle'
        New-Item -ItemType Directory -Path $oracleDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $oracleDir 'path-tag') -Value $Arg2 -NoNewline
        if (Test-Path $Counts) { Remove-Item $Counts -Force }
        # The mark the sentinel refuses to run under. Set here and nowhere else:
        # a sentinel on the device under test would prove the device can reach
        # the oracle, which is the one thing a SILENCE phase asserts is
        # impossible.
        $env:TWINVPN_DISPOSABLE_GUEST     = '1'
        $env:TWINVPN_ORACLE_CONTROL_BY    = 'controller'
        $env:TWINVPN_ORACLE_TOPOLOGY      = 'in-box'
        Invoke-Native {
            & $Bash -lc "cd /c/twinvpn && build/ci/leak-probe.sh beacon --seconds $Arg1 --counts-file /c/twinvpn/counts.env"
        } | Write-Output
        if ($LASTEXITCODE -ne 0) { throw "the beacon window exited $LASTEXITCODE" }
        if (-not (Test-Path $Counts)) { throw "the beacon window wrote no counts at $Counts" }
    }

    'armed-check' {
        # Read back from the ENGINE, never assumed, and recorded rather than
        # enforced here: if the filters are absent the ARMED window measures an
        # unprotected host, and an unprotected host BEACONS -- so the oracle
        # sees arrivals during SILENCE and the row fails. There is no path from
        # a missing filter set to a false pass, which is why this can be a
        # measurement instead of an abort.
        $env:TWINVPN_WINDOWS_TEST    = '1'
        $env:TWINVPN_EXPECT_FILTERS  = '1'
        Invoke-Native {
            & $Precond --nocapture --test-threads=1 twinvpns_own_filters_are_installed_right_now
        } | Write-Output
        Say "TWINVPN_ARMED_CHECK_EXIT $LASTEXITCODE"
    }

    'kill' {
        # `taskkill /F`, not `net down` or `sc stop`, deliberately: the
        # invariant is about UNEXPECTED disappearance, and a graceful stop is a
        # path the product controls and can tidy up on.
        Invoke-Native { & taskkill.exe /F /IM twinvpnsvc.exe /T } | Write-Output
        foreach ($i in 1..20) {
            if (-not (Get-Process -Name twinvpnsvc -ErrorAction SilentlyContinue)) { break }
            Start-Sleep -Seconds 1
        }
        if (Get-Process -Name twinvpnsvc -ErrorAction SilentlyContinue) {
            throw 'twinvpnsvc.exe is still running; the tunnel was not terminated'
        }
        Transition 'MANAGEMENT_READY' 'SERVICE_KILLED'
        Say 'twinvpnsvc.exe is gone'
    }

    'restore' {
        Invoke-Native { & sc.exe delete TwinVPNService } | Out-Null
        Invoke-Native { & sc.exe create TwinVPNService binPath= "$Svc" start= demand } | Out-Null
        Invoke-Native { & sc.exe start TwinVPNService } | Out-Null
        Transition 'SERVICE_KILLED' 'SERVICE_RUNNING'
        foreach ($i in 1..30) {
            Invoke-Native { & $Ctl status get } | Out-Null
            if ($LASTEXITCODE -eq 0) { Transition 'SERVICE_RUNNING' 'MANAGEMENT_READY'; break }
            Start-Sleep -Seconds 1
        }
        $out = Invoke-Native { & $Ctl --output json net up }
        Say "TWINVPN_RESTORE_NET_UP_EXIT $LASTEXITCODE"
        Say $out.Trim()
    }
}
