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
                 'route-identity', 'net-up', 'dns-protected', 'dns-unprotected',
                 'beacon', 'armed-check', 'kill', 'restore')]
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
$Wintun  = Join-Path $Bin 'wintun.dll'
$Counts  = Join-Path $Root 'counts.env'
# Where the service writes its own log. Under the SCM a service has no console
# and its stdout is discarded, so without this the refusal that names WHY a
# start failed is unobservable and only an exit code survives. The service
# reads TWINVPN_LOG_FILE from its `Environment` registry value (below).
$SvcLog  = Join-Path $Root 'twinvpnsvc.log'
# THE LAB SEED, read by a `lab-seed` build of the service and by nothing else.
# `enforce::arm` needs a local overlay allocation and one peer with a verified
# tunnel-key binding, both of which live only in memory and have no production
# writer yet, so without this `net up` refuses AUTH.IDENTITY_MISSING and every
# phase after BASELINE is silent. `ci-windows-killswitch.sh` pushes the file the
# lab peer generated on L1; the service's `Environment` value below names it.
$SeedFile = Join-Path $Root 'lab-seed.json'
# ADR-0020 §11.9's Windows row and TwinVPN.wxs's `StoreDirectory`: the
# installer creates the store root with its ACL; the service creates `tier1`
# beneath it on first use and refuses to start if the root is absent
# (AUTH.KEY_STORE_UNAVAILABLE). Run 11 measured exactly that refusal: the
# service started, exited 71 before binding its pipe, and nothing here had
# created the directory.
$StoreRoot = 'C:\ProgramData\TwinVPN\store'

# THE GUEST'S HALF OF THE ADDRESS PLAN. Switch A is the guest's own link;
# everything else is reachable only through the default route. Two ranges are
# excluded by construction and the exclusion is the design:
#   * 169.254.0.0/16 and fe80::/10 -- class 9 PERMITS link-local;
#   * anything on-link with this guest -- class 4 PERMITS local network access,
#     which is ALLOW in every routing mode (wfp/mod.rs:576).
#
# 100.64.0.0/10 AND fd7c:9e5d:2a10::/48 USED TO BE EXCLUDED TOO, on the ground
# that they are the Tier-1 baseline deny floor and a leg addressed there could
# never arrive. That reasoning has INVERTED and the beacon target is now
# deliberately inside it:
#
#   * In RoutingMode::TwinnetOnly the Tier-1 PROTECTED scope is that floor plus
#     the authorized peers' /32 and /128 host routes and nothing else. A target
#     outside it -- 10.78.0.1, say -- is not governed at all, so an ARMED host
#     permits the beacon and the SILENCE phase fails BY DESIGN.
#   * The two postures differ by exactly the Tier-2 overlay permit, which is
#     INTERFACE-scoped, so the same destination is permitted through the tunnel
#     and denied off it. That is what makes TUNNELLED arrive and ARMED silent.
#   * BASELINE still reaches it because BASELINE runs before the service exists
#     and this lane registers the service with `sc.exe create`, never the MSI,
#     so the KS-19 boot-time filter set is never installed. Assert-Reachable
#     below MEASURES that rather than assuming it.
#
# One destination, two paths, disjoint sources. See scripts/twinvpn-l1.ps1's
# header and lab/twinoracle/README.md section 3.1.
$GuestV4   = '10.77.0.10'; $GuestV4Len = 24; $GatewayV4 = '10.77.0.1'
$GuestV6   = 'fd77:7717:d0c::10'; $GuestV6Len = 64; $GatewayV6 = 'fd77:7717:d0c::1'
# The PEER's overlay addresses: the oracle's HTTP listener and the protected
# DNS relay both live there, on L1's `twinpeer` adapter.
$OracleV4  = '100.64.1.2'
$OraclePort = 8080   # twinvpn-l1.ps1 binds and advertises 8080; port 80 belongs to HTTP.sys on L1
$OracleV6  = 'fd7c:9e5d:2a10:1::2'
# The UNPROTECTED resolver, on switch B. BASELINE only.
$ResolverV4 = '10.78.0.53'
$ResolverV6 = 'fd78:7717:d0c::53'
# The PROTECTED resolver: the same overlay addresses, reachable only through
# the tunnel. `dns-protected` SWITCHES the stub to these rather than adding
# them -- Windows would otherwise query both, a `p`-tagged phase would collect
# an arrival the oracle maps `u`, and that disagreement is an inconclusive
# reason (twinoracle evidence.rs:448-465).
$ProtResolverV4 = $OracleV4
$ProtResolverV6 = $OracleV6

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
function Register-TwinVpnService {
    # THE WAY THE MSI REGISTERS IT (shells/windows/packaging/TwinVPN.wxs):
    # LocalSystem, the unrestricted service SID, and RequiredPrivileges trimmed
    # to ADR-0016 §11.9's three. The trim is load-bearing: the service verifies
    # its own posture at startup and refuses a token holding SeDebugPrivilege or
    # SeTcbPrivilege, which a LocalSystem service registered by a bare
    # `sc.exe create` always does.
    Invoke-Native { & sc.exe create TwinVPNService binPath= "$Svc" start= demand } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe create TwinVPNService exited $LASTEXITCODE" }
    Invoke-Native { & sc.exe sidtype TwinVPNService unrestricted } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe sidtype TwinVPNService exited $LASTEXITCODE" }
    Invoke-Native { & sc.exe privs TwinVPNService SeChangeNotifyPrivilege/SeImpersonatePrivilege/SeLoadDriverPrivilege } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe privs TwinVPNService exited $LASTEXITCODE" }
    # PS-12a's local groups, which the package creates and the service only
    # resolves: the listener refuses to bind its pipe without them, and a
    # client's scopes come from membership. The lane's user drives `net up`,
    # so it is an operator here the way README §4 step 8 makes a person one.
    # Idempotent, because step 8 registers the service a second time.
    foreach ($g in @('TwinVPN Users', 'TwinVPN Operators')) {
        if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) {
            New-LocalGroup -Name $g -Description 'TwinVPN PS-12a (lane-created, as the MSI would)' | Out-Null
        }
        $members = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
        if (-not ($members -match "\\$([regex]::Escape($env:USERNAME))$")) {
            Add-LocalGroupMember -Group $g -Member $env:USERNAME
        }
    }
    # The store root, with the MSI's ACL (TwinVPN.wxs `StoreDirectory`): SYSTEM
    # and Administrators full, Users denied, nothing inheritable. The root only;
    # `tier1` is the service's to create.
    if (-not (Test-Path $StoreRoot)) { New-Item -ItemType Directory -Path $StoreRoot -Force | Out-Null }
    # NO DENY ACE FOR USERS, AND INHERITABLE GRANTS. Measured on 2026-09-03 as
    # NT AUTHORITY\SYSTEM: its token carries BUILTIN\Users, so `/deny Users:(F)`
    # denied the service's own file creates ("Access to the path ... is
    # denied") while still allowing directory creation -- which is why the
    # store's tier1 directory appeared and `net up` then failed writing
    # resolver.restore as AUTH.KEY_STORE_UNAVAILABLE. With inheritance removed,
    # an absent ACE already denies everyone else; (OI)(CI) makes the grants
    # reach the files the service creates inside.
    Invoke-Native { & icacls.exe $StoreRoot /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' } | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls exited $LASTEXITCODE setting the store root's ACL" }
    # The service's process environment, the way the SCM reads it: a
    # REG_MULTI_SZ `Environment` under the service key. `sc.exe delete` removes
    # the key, so this is re-applied on every registration.
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TwinVPNService' `
        -Name Environment -Type MultiString `
        -Value @("TWINVPN_LOG_FILE=$SvcLog", "TWINVPN_LAB_SEED_FILE=$SeedFile")
}

# Polls the management endpoint for up to $Seconds, and stops early once the
# SCM says the service is STOPPED: a refused start used to be waited out for
# the full window, and then reported as a bind timeout it never was.
function Wait-ManagementEndpoint([int] $Seconds = 30) {
    foreach ($i in 1..$Seconds) {
        Invoke-Native { & $Ctl status get } | Out-Null
        if ($LASTEXITCODE -eq 0) { return $true }
        $q = Invoke-Native { & sc.exe query TwinVPNService }
        if ($q -match 'STATE\s*:\s*\d+\s+STOPPED') { return $false }
        Start-Sleep -Seconds 1
    }
    return $false
}

# What the SCM and the service itself have to say, as lines the lane scrapes.
# Printed on every path so a success also records the state it reached.
function Report-ServiceState {
    $q = Invoke-Native { & sc.exe query TwinVPNService }
    $state = if ($q -match 'STATE\s*:\s*\d+\s+([A-Z_]+)') { $Matches[1] } else { 'UNQUERYABLE' }
    $w32   = if ($q -match 'WIN32_EXIT_CODE\s*:\s*(\d+)') { $Matches[1] } else { '?' }
    $spec  = if ($q -match 'SERVICE_EXIT_CODE\s*:\s*(\d+)') { $Matches[1] } else { '?' }
    $alive = [bool](Get-Process -Name twinvpnsvc -ErrorAction SilentlyContinue)
    Say "TWINVPN_SERVICE_STATE state=$state win32_exit=$w32 service_exit=$spec process_alive=$alive"
    Say 'TWINVPN_SERVICE_LOG_BEGIN'
    if (Test-Path $SvcLog) { Get-Content -LiteralPath $SvcLog -Tail 60 | ForEach-Object { Say $_ } }
    else { Say "(no service log at ${SvcLog}: the service never reached its logger, or the SCM did not pass TWINVPN_LOG_FILE)" }
    Say 'TWINVPN_SERVICE_LOG_END'
    Say 'TWINVPN_SCM_EVENTS_BEGIN'
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager' } `
                 -MaxEvents 200 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'TwinVPN' } | Select-Object -First 10 |
        ForEach-Object { Say ("{0:o} id={1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ')) }
    Say 'TWINVPN_SCM_EVENTS_END'
}

function Transition([string] $From, [string] $To) {
    Write-Output "TWINVPN_LIFECYCLE_TRANSITION $From->$To"
}

function Get-GuestAdapter {
    $a = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object ifIndex | Select-Object -First 1
    if (-not $a) { throw 'the guest has no network adapter in the Up state' }
    return $a
}

# THE UNDERLAY NIC, FOUND BY THE ADDRESS `prepare` PUT ON IT.
#
# Get-GuestAdapter picks the lowest-ifIndex adapter in the Up state, which is
# exactly right before the tunnel exists and a coin flip afterwards -- the DNS
# steps below run AFTER `net up`, when the overlay adapter is Up too. Putting
# the stub resolver on the OVERLAY interface would put it precisely where the
# product's own DNS programme rewrites it (dns.rs:295-306 sets the overlay
# interface's servers and its NRPT rules and nothing else), so the guest would
# silently keep querying the unprotected resolver and the TUNNELLED window would
# collect a DNS arrival the oracle maps `u` inside a `p`-tagged phase.
function Get-UnderlayInterfaceIndex {
    $a = Get-NetIPAddress -IPAddress $GuestV4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $a) {
        throw ("the guest holds no $GuestV4, so its underlay NIC cannot be " +
               "identified. The prepare step assigns it; either that step did " +
               "not run or something removed the address.")
    }
    return $a.InterfaceIndex
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
    # RETRIED, and read from TcpTestSucceeded rather than the Quiet boolean: run
    # 10's one-shot quiet probe said no while the detailed probe a second later
    # connected, so the first SYN through a freshly configured adapter, a fresh
    # neighbour entry and a fresh firewall rule is not the measurement.
    $ok = $false
    foreach ($attempt in 1..10) {
        $r = Test-NetConnection -ComputerName $Address -Port $OraclePort -WarningAction SilentlyContinue
        if ($r.TcpTestSucceeded) { $ok = $true; break }
        Start-Sleep -Seconds 2
    }
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
        # The UNPROTECTED resolver, off-link like the oracle. BASELINE runs
        # against this one; `dns-protected` switches to the overlay relay once
        # the tunnel is up. Nothing in the PRODUCT binds a DNS listener
        # (enforce.rs:265-289 assembles denied_dns_policy() with empty stub
        # addresses), so the protected relay is the lab's, and the evidence's
        # `dns_protected_resolver` says exactly that.
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
        foreach ($f in @($Ctl, $Svc, $Precond, $Wintun)) {
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
        Register-TwinVpnService
        $start = Invoke-Native { & sc.exe start TwinVPNService }
        if ($LASTEXITCODE -ne 0) { Say $start.Trim(); Report-ServiceState; throw "sc.exe start TwinVPNService exited $LASTEXITCODE" }
        Transition 'SERVICE_ABSENT' 'SERVICE_RUNNING'
        $ready = Wait-ManagementEndpoint 30
        Report-ServiceState
        if (-not $ready) { throw 'TwinVPNService started but never bound its management endpoint; TWINVPN_SERVICE_STATE above says what the SCM saw and TWINVPN_SERVICE_LOG what the service said' }
        Transition 'SERVICE_RUNNING' 'MANAGEMENT_READY'
        Say (Invoke-Native { & $Ctl --output json status get }).Trim()
    }

    'route-identity' {
        # MEASURED, never declared. `PATH_IDENTITY_PREREQUISITES` refuses a row
        # whose two path identities are equal, and a pair of differing constants
        # would satisfy that check while describing nothing.
        #
        # TOWARD THE BEACON, NOT ALONG THE DEFAULT ROUTE, and that is a fix
        # rather than a refinement. `RoutingMode::TwinnetOnly` installs NO
        # default route -- the match arm in twinvpn-route/src/program.rs is
        # empty, and enforce.rs confirms that no exit node means no default
        # route in either family -- so after `net up` the default route is still
        # the underlay one. Reading it returned the SAME string in both phases,
        # `protected_path_identity` equalled `unprotected_path_identity`, and
        # build/acceptance/adjudication.py failed the row.
        #
        # `Find-NetRoute` answers the question that actually matters -- which
        # interface and which SOURCE address this guest would use to reach the
        # oracle right now -- and its two objects are the same pair
        # `Assert-OffLink` above unpacks: a NetIPAddress and a NetRoute. The
        # source it reports is exactly what the oracle records as the arrival
        # source, so the two halves of the evidence are the same measurement.
        $sel   = Find-NetRoute -RemoteIPAddress $OracleV4 -ErrorAction SilentlyContinue
        $route = $sel | Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
        $src   = $sel | Where-Object { $_.PSObject.Properties['IPAddress'] } | Select-Object -First 1
        if ($null -eq $route) { return }   # unreadable == not established
        $nic = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction SilentlyContinue
        Say ("if{0}:{1}:{2}" -f $route.ifIndex, $nic.Name, $src.IPAddress)
    }

    # THE STUB RESOLVER, SWITCHED RATHER THAN EXTENDED. The product programs no
    # resolver of its own -- the Windows DNS programme only ever sets the
    # OVERLAY interface's servers and NRPT rules, and `assemble` hands it an
    # empty stub list -- so pointing the guest at the protected relay is a LAB
    # action standing in for something TwinVPN does not do. It is still honest
    # evidence for THIS criterion, whose claim is that an armed host BLOCKS the
    # resolver, not that it configures one; `dns_protected_resolver` in the
    # evidence names the relay so no reader infers otherwise.
    #
    # Both families in one call, because Set-DnsClientServerAddress REPLACES the
    # list. Adding the protected pair beside the unprotected one would let
    # Windows query both, a `p`-tagged phase would collect an arrival the oracle
    # maps `u`, and that disagreement is an inconclusive reason.
    'dns-protected' {
        # BOTH interfaces, not only the underlay. Run 33748188192 set the
        # protected resolver on the underlay adapter alone and the oracle saw
        # zero DNS while tunnelled, with the beacon's lookups returning at
        # once: once twin0 exists the product programs its resolver list to
        # nothing, Windows nslookup takes its "default server" from the
        # lowest-metric interface, and an interface with no server fails the
        # lookup without sending a packet. The overlay interface is the one the
        # route to the beacon target selects, so it gets the same servers.
        $idx = Get-UnderlayInterfaceIndex
        $route = Find-NetRoute -RemoteIPAddress $OracleV4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.PSObject.Properties['DestinationPrefix'] } | Select-Object -First 1
        $targets = @($idx)
        if ($route -and $route.InterfaceIndex -ne $idx) { $targets += $route.InterfaceIndex }
        foreach ($i in $targets) {
            Set-DnsClientServerAddress -InterfaceIndex $i `
                -ServerAddresses @($ProtResolverV4, $ProtResolverV6) | Out-Null
            Say "dns servers on if${i}: $ProtResolverV4, $ProtResolverV6 (protected; reachable only through the tunnel)"
        }
        # What the resolver path looks like from here, printed rather than
        # assumed: every interface's server list, and one lookup of a name in
        # the beacon zone through nslookup exactly as leak-probe.sh issues it.
        # The oracle answers REFUSED for a name without a probe token, which
        # is itself the proof that the query reached it.
        Get-DnsClientServerAddress -AddressFamily IPv4, IPv6 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            ForEach-Object { Say ("TWINVPN_DNS_SERVERS if{0} {1}: {2}" -f $_.InterfaceIndex, $_.InterfaceAlias, ($_.ServerAddresses -join ',')) }
        $probe = Invoke-Native { & nslookup.exe -timeout=2 -retry=1 "diag.leak.oracle.twinvpn.test" }
        Say "TWINVPN_DNS_DIAG_BEGIN"
        Say ($probe.Trim() -replace "`r", '')
        Say "TWINVPN_DNS_DIAG_END"
    }

    # The BASELINE configuration, restorable for a diagnosis. It is deliberately
    # NOT used before the ARMED window: that window has to test the TUNNELLED
    # configuration with the tunnel dead, and pointing the stub back at a
    # reachable resolver would measure something else entirely.
    'dns-unprotected' {
        $idx = Get-UnderlayInterfaceIndex
        Set-DnsClientServerAddress -InterfaceIndex $idx `
            -ServerAddresses @($ResolverV4, $ResolverV6) | Out-Null
        Say "dns servers on if${idx}: $ResolverV4, $ResolverV6 (unprotected)"
    }

    'net-up' {
        # NOT FATAL HERE. A refusal is a measured fact about the product on
        # this host, and aborting on it would destroy the evidence that says
        # WHY the row is red. The exit code and the refusal are printed and the
        # lane records them verbatim; which reason code comes back is read from
        # the output, never predicted here.
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
        # One second per probe: everything here is one hop away, and during
        # the ARMED window every probe is blocked and waits its whole timeout.
        # Run 33748188192 measured 11 attempts in a 120 s window at the 3 s
        # default and fell short of the oracle's 60-per-family floor.
        $env:TWINVPN_PROBE_TIMEOUT_S      = '1'
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
        Register-TwinVpnService
        Invoke-Native { & sc.exe start TwinVPNService } | Out-Null
        Transition 'SERVICE_KILLED' 'SERVICE_RUNNING'
        if (Wait-ManagementEndpoint 30) { Transition 'SERVICE_RUNNING' 'MANAGEMENT_READY' }
        Report-ServiceState
        $out = Invoke-Native { & $Ctl --output json net up }
        Say "TWINVPN_RESTORE_NET_UP_EXIT $LASTEXITCODE"
        Say $out.Trim()
    }
}
