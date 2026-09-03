<#
.SYNOPSIS
  The L1 controller for `WINDOWS-WFP-KILLSWITCH`: build a guest image, stand up
  the lab fabric and the leak oracle in-box, create a disposable nested Hyper-V
  guest, run the kill-switch sequence against it, take the evidence out, destroy
  everything.

.DESCRIPTION
  Runs on a GITHUB-HOSTED `windows-2025` runner. No self-hosted runner, no
  golden VHDX, no external oracle host, no standing sentinel host, no repository
  variables. Everything below is created and destroyed inside the job.

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
    * **The guest is a DIFFERENCING disk over a per-run base image, deleted
      afterwards, with automatic checkpoints off.** There is no `--reset` to
      satisfy, because the guest never survives a run, and a checkpoint taken
      mid-run would capture exactly the dirty state being discarded.

  ## Why the observers are here rather than on a third machine

  The oracle must be somewhere the guest can reach ONLY by emitting a packet
  that leaves it, and the sentinel must present an address the guest never
  presents. Two internal switches give both, with no NAT anywhere:

    * switch A is the guest's own link. The guest holds 10.77.0.10 and
      fd77:7717:d0c::10 and routes everything else through this host.
    * switch B carries the oracle's authoritative DNS (10.78.0.1,
      fd78:7717:d0c::1), the sentinel's egress identity (…0.2, …::2), the
      unprotected resolver (…0.53, …::53) and the PROTECTED relay's source
      (…0.54, …::54). The guest has NO route to that segment except its default
      route, which is the property that matters: TwinVPN's class-4 filter
      PERMITS the guest's on-link prefixes and its class-9 filter PERMITS
      link-local, so an observer on either would be reachable while armed and
      the SILENCE phase would fail for a reason that is not a leak.

  ## The beacon target is INSIDE the overlay, and that reverses an old rule

  `lab/twinoracle/README.md` §3.1 tells a listener to AVOID 100.64.0.0/10 and
  fd7c:9e5d:2a10::/48, on the ground that they are the Tier-1 baseline deny
  floor and a beacon addressed there could never arrive. This lane departs from
  that rule deliberately, and the departure is what makes the criterion
  measurable at all:

    * In `RoutingMode::TwinnetOnly` the Tier-1 PROTECTED scope is that floor
      plus the authorized peers' /32 and /128 host routes and nothing else
      (`twinvpn-core/src/enforce.rs:508-518`,
      `twinvpn-platform-windows/src/wfp/filters.rs:598-608`). A beacon aimed at
      10.78.0.1 is therefore OUT of scope: an armed host permits it, and the
      ARMED SILENCE phase fails BY DESIGN rather than by defect.
    * BASELINE still reaches the same address, because BASELINE runs before the
      service is ever started AND this lane registers the service with
      `sc.exe create` rather than with the MSI, so the KS-19 boot-time filter
      set is never installed. No TwinVPN filter exists at that moment and the
      guest's default route carries the beacon to this host, which holds the
      address on the `twinpeer` adapter.
    * The two postures differ by exactly the Tier-2 overlay permit, which is
      INTERFACE-scoped (`wfp/filters.rs:920-950`), so the same destination is
      permitted through the tunnel and denied off it.

  One destination, two paths, disjoint sources — the stronger form of the
  evidence, because nothing about the target can explain the difference. IF THIS
  LANE EVER INSTALLS THE MSI the boot artifact makes filters live during
  BASELINE, the second bullet reverses, and the beacon must move back off the
  overlay; `lab/twinoracle/README.md` §3.1 carries the same warning.

  The residual weakness, stated rather than hidden and recorded in
  `sentinel_host`: a same-host sentinel proves the oracle was alive and its
  listeners bound, and cannot prove a data-plane route between sentinel and
  oracle stayed up, because there is no such route to break.

  ## The control token stays on this machine

  The guest holds no oracle credential. A correct kill switch blocks the guest's
  control-plane posts during the armed window, and the missing attempt counts
  would make the oracle grade the session INCONCLUSIVE. So this host opens the
  session, declares phases and posts the counts the guest measured; the guest
  runs the data plane. See `build/ci/ci-windows-killswitch.sh`.

.EXAMPLE
  .\twinvpn-l1.ps1 -Action preflight; .\twinvpn-l1.ps1 -Action prefetch-iso
  # ... build the binaries while it downloads ...
  .\twinvpn-l1.ps1 -Action build-image
  .\twinvpn-l1.ps1 -Action run -RepoPath $env:GITHUB_WORKSPACE -EvidenceOut ...
  .\twinvpn-l1.ps1 -Action destroy    # always, including after a cancellation
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('preflight', 'prefetch-iso', 'build-image', 'run', 'destroy', 'guest-exec', 'push', 'fetch')]
    [string] $Action,

    [string] $RepoPath,
    [string] $EvidenceOut,

    # DETERMINISTIC, and that is a fix rather than a simplification. The name
    # used to default to a fresh GUID per invocation, so the workflow's
    # `if: always()` destroy step computed a name that had never existed and
    # tore down nothing.
    [string] $VmName = 'twinvpn-ks',
    # Defaults to `twinvpn-l1` on whichever of C: and D: has more room: the
    # hosted fleet's free space varies by several GB run to run (run 5 saw
    # 28.5 GB on C: where run 4 saw 34.5), and D: is the larger workspace disk
    # on some images.
    [string] $VmRoot = '',

    [string] $Step, [string] $Arg1, [string] $Arg2,
    [string] $LocalPath, [string] $RemotePath,

    [int] $MemoryGB = 4,
    [int] $Cpus = 2,
    [int] $BootTimeoutMinutes = 20,
    [int] $RunTimeoutMinutes = 45
)

$ErrorActionPreference = 'Stop'

$Here      = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $VmRoot) {
    $roomiest = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -in 'C', 'D' } |
                Sort-Object Free -Descending | Select-Object -First 1
    $VmRoot = Join-Path ($roomiest.Root) 'twinvpn-l1'
}
$RunDir    = Join-Path $VmRoot 'run'
$OraclePort = 8080   # see Start-Observers: port 80 belongs to HTTP.sys on Windows
$BaseVhd   = Join-Path $VmRoot 'base.vhdx'
$DiffVhd   = Join-Path $RunDir "$VmName.vhdx"
$PidFile   = Join-Path $RunDir 'observers.pid'
$GuestUser = 'twinvpn'
$Zone      = 'leak.oracle.twinvpn.test'
$FwRule    = 'twinvpn-lab-observers'

# THE ADDRESS PLAN. One place, because the guest script, the oracle flags, the
# resolver map and the sentinel must agree; a second copy that drifted would
# surface as an INCONCLUSIVE session with no obvious cause.
$SwGuest = 'twinvpn-guest'; $SwOracle = 'twinvpn-oracle'
$NicGuest = "vEthernet ($SwGuest)"; $NicOracle = "vEthernet ($SwOracle)"
$L1GuestV4 = '10.77.0.1'; $L1GuestV6 = 'fd77:7717:d0c::1'
$OracleV4 = '10.78.0.1'; $SentinelV4 = '10.78.0.2'; $ResolverV4 = '10.78.0.53'
$OracleV6 = 'fd78:7717:d0c::1'; $SentinelV6 = 'fd78:7717:d0c::2'; $ResolverV6 = 'fd78:7717:d0c::53'
# THE LAB PEER'S OVERLAY ADDRESSES, and therefore the beacon target and the
# protected resolver's listener. See the header: the target must be inside the
# Tier-1 protected scope or an armed host permits it. AP-2 reserves
# 100.64.0.0/24 and fd7c:9e5d:2a10:ffff::/64, so this lane allocates from
# 100.64.1.0/24 and fd7c:9e5d:2a10:1::/64; the guest's own overlay is …1.1.
$PeerOverlayV4 = '100.64.1.2'; $PeerOverlayV6 = 'fd7c:9e5d:2a10:1::2'
$PeerAdapter = 'twinpeer'; $PeerEndpointPort = 51820
# The PROTECTED relay's SOURCE, which is the identity the oracle derives `:p`
# from. It is NOT the address that relay listens on: the listener is on the peer
# overlay, reachable only through the tunnel, while the source is on switch B
# beside the unprotected relay's, so the two DNS identities are disjoint.
$ProtResolverSrcV4 = '10.78.0.54'; $ProtResolverSrcV6 = 'fd78:7717:d0c::54'

function Assert-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = [Security.Principal.WindowsPrincipal]::new($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run elevated. Every Hyper-V cmdlet below needs it.' }
}

function Assert-Hypervisor {
    if (-not (Get-Service -Name vmms -ErrorAction SilentlyContinue)) {
        throw ('The Hyper-V Virtual Machine Management service is not present. ' +
               'The hosted windows-2025 image installs the Hyper-V role, ' +
               'Hyper-V-PowerShell, HypervisorPlatform and VirtualMachinePlatform ' +
               'at image-build time, so its absence means the image changed and ' +
               'this lane cannot produce evidence here.')
    }
    if ((Get-Service -Name vmms).Status -ne 'Running') { throw 'vmms is installed but not running.' }
    if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) { throw 'the Hyper-V PowerShell module is absent.' }
    Write-Host "vmms: $((Get-Service vmms).Status); hypervisor present: $((Get-ComputerInfo -Property HyperVisorPresent).HyperVisorPresent)"
}

# Bytes from the platform CSPRNG, as hex. NOT `Get-Random`, a seeded PRNG: these
# values are the guest's administrator password and the oracle's control bearer.
# `Create()` plus the instance `GetBytes` rather than the static `GetBytes(int)`,
# because the static form arrived in .NET 6 and this file is also run by Windows
# PowerShell 5.1, the shell that carries the Hyper-V cmdlets natively.
function New-Secret([int] $Bytes = 24) {
    $buf = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buf) } finally { $rng.Dispose() }
    ($buf | ForEach-Object { $_.ToString('x2') }) -join ''
}

# `D:\a\twinvpn` -> `/d/a/twinvpn`. Any drive letter: a hosted runner's workspace
# is not always on C:, and a hard-coded `^C:` would produce a path git-bash
# cannot cd into.
function ConvertTo-BashPath([string] $Path) {
    "/" + $Path.Substring(0, 1).ToLower() + ($Path.Substring(2) -replace '\\', '/')
}

function Get-GuestCredential {
    # Imported BY PATH when autoload fails: under a PSModulePath that a
    # foreign shell rewrote, `ConvertTo-SecureString` is "found but the module
    # could not be loaded", and the full path needs no search.
    if (-not (Get-Command ConvertTo-SecureString -ErrorAction SilentlyContinue)) {
        Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security') -ErrorAction Stop
    }
    $pw = $env:TWINVPN_GUEST_PASSWORD
    if (-not $pw) { throw 'TWINVPN_GUEST_PASSWORD is not in this process environment; -Action run sets it for its children.' }
    New-Object System.Management.Automation.PSCredential(
        $GuestUser, (ConvertTo-SecureString $pw -AsPlainText -Force))
}

function New-GuestSession {
    $cred = Get-GuestCredential
    $s = New-PSSession -VMName $VmName -Credential $cred -ErrorAction SilentlyContinue
    if (-not $s) {
        # The other documented spelling of a local account. Two spellings, tried
        # once each -- not a retry loop around a guess.
        $cred2 = New-Object System.Management.Automation.PSCredential(
            ".\$GuestUser", $cred.Password)
        $s = New-PSSession -VMName $VmName -Credential $cred2 -ErrorAction SilentlyContinue
    }
    if (-not $s) { throw "no PowerShell Direct session to $VmName" }
    return $s
}

function New-Fabric {
    foreach ($sw in @($SwGuest, $SwOracle)) {
        if (-not (Get-VMSwitch -Name $sw -ErrorAction SilentlyContinue)) { New-VMSwitch -Name $sw -SwitchType Internal | Out-Null }
    }
    $plan = @(
        @{ Nic = $NicGuest;  V4 = @($L1GuestV4); V6 = @($L1GuestV6) },
        @{ Nic = $NicOracle; V4 = @($OracleV4, $SentinelV4, $ResolverV4, $ProtResolverSrcV4)
           V6 = @($OracleV6, $SentinelV6, $ResolverV6, $ProtResolverSrcV6) })
    foreach ($p in $plan) {
        # The host vNIC appears when the switch does, but not always in the same
        # instant. Waited for, so a race reads as a race rather than as "the
        # switch was not created".
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Get-NetAdapter -Name $p.Nic -ErrorAction SilentlyContinue) -and
               (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
        $idx = (Get-NetAdapter -Name $p.Nic).ifIndex
        Get-NetIPAddress -InterfaceIndex $idx -ErrorAction SilentlyContinue |
            Where-Object { $_.PrefixOrigin -ne 'WellKnown' } |
            Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        foreach ($a in $p.V4) { New-NetIPAddress -InterfaceIndex $idx -IPAddress $a -PrefixLength 24 | Out-Null }
        foreach ($a in $p.V6) { New-NetIPAddress -InterfaceIndex $idx -IPAddress $a -PrefixLength 64 | Out-Null }
        foreach ($fam in @('IPv4', 'IPv6')) {
            # FORWARDING, because the guest's packets to switch B are routed
            # here; WEAK HOST because their destination is an address on the
            # OTHER interface and the reply's source is likewise. Windows uses
            # the strong host model on both send and receive by default, so
            # without these the guest's beacons are dropped by this host and the
            # SILENCE phase would pass for a reason that is not the product.
            Set-NetIPInterface -InterfaceIndex $idx -AddressFamily $fam `
                -Forwarding Enabled -WeakHostReceive Enabled -WeakHostSend Enabled
        }
    }
    # NARROW firewall rules rather than a disabled profile: only the observers'
    # own addresses and ports, removed again by -Action destroy.
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    # The oracle's port is $OraclePort, not 80 (see Start-Observers). Run 8
    # measured this rule still on 80: the guest could not open tcp/8080 and
    # could not even ping its gateway, because the host vNICs sit in the
    # Public profile where everything inbound is dropped unless a rule allows
    # it. ICMP echo is allowed on the lab addresses so the guest's own
    # reachability diagnostics can tell a dead listener from a dead link.
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $OraclePort `
        -LocalAddress @($OracleV4, $OracleV6, $PeerOverlayV4, $PeerOverlayV6) | Out-Null
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort 53 `
        -LocalAddress @($OracleV4, $OracleV6, $ResolverV4, $ResolverV6,
                        $PeerOverlayV4, $PeerOverlayV6,
                        $ProtResolverSrcV4, $ProtResolverSrcV6) | Out-Null
    # THE TUNNEL ITSELF. The guest's Noise initiation is a UDP datagram to this
    # host's switch-A address; without this the handshake never reaches the peer
    # and `net up` refuses for a reason that is about the lab, not the product.
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -Protocol UDP -LocalPort $PeerEndpointPort -LocalAddress @($L1GuestV4) | Out-Null
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -Protocol ICMPv4 -IcmpType 8 `
        -LocalAddress @($L1GuestV4, $OracleV4, $SentinelV4, $ResolverV4) | Out-Null
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -Protocol ICMPv6 -IcmpType 128 `
        -LocalAddress @($L1GuestV6, $OracleV6, $SentinelV6, $ResolverV6) | Out-Null
    # AND an allow scoped to the two lab vNICs themselves. Run 9 had ICMP
    # answered on both hops and tcp/8080 still refused with the port rule in
    # place; the guest is the only peer on these switches, so an
    # interface-scoped allow is as narrow as the port rule in practice and
    # removes the whole class. Blocked packets are logged so the next refusal
    # names its rule instead of being inferred.
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -InterfaceAlias @($NicGuest, $NicOracle) | Out-Null
    Set-NetFirewallProfile -All -LogBlocked True -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -ErrorAction SilentlyContinue
    Write-Host "fabric up: $SwGuest ($L1GuestV4, $L1GuestV6) and $SwOracle ($OracleV4, $OracleV6)"
}

function Remove-Fabric {
    Remove-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue
    foreach ($sw in @($SwGuest, $SwOracle)) { Remove-VMSwitch -Name $sw -Force -ErrorAction SilentlyContinue }
}

function Start-Observers([string] $Repo) {
    New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
    $controlToken  = Join-Path $RunDir 'control.token'
    $sentinelToken = Join-Path $RunDir 'sentinel.token'
    New-Secret 24 | Set-Content -LiteralPath $controlToken  -NoNewline
    New-Secret 24 | Set-Content -LiteralPath $sentinelToken -NoNewline

    $oracle = Join-Path $Repo 'lab\target\release\twinoracle.exe'
    if (-not (Test-Path $oracle)) { throw "twinoracle.exe was not built at $oracle" }
    $peer = Join-Path $Repo 'lab\target\release\twinpeer.exe'
    if (-not (Test-Path $peer)) { throw "twinpeer.exe was not built at $peer" }
    $pids = @()

    # WHO ELSE IS ON THESE PORTS, recorded before any bind so a refusal names
    # its cause. Internet Connection Sharing (the `SharedAccess` service, which
    # backs Hyper-V's Default Switch / WSL NAT) runs a DNS proxy on UDP 53 of
    # every internal-switch address; this job uses neither the Default Switch
    # nor WSL, so it is stopped for the job on an ephemeral runner.
    $ics = Get-Service SharedAccess -ErrorAction SilentlyContinue
    if ($ics -and $ics.Status -eq 'Running') {
        Write-Host 'stopping Internet Connection Sharing (SharedAccess) for the job: it holds UDP 53 on internal switches'
        Stop-Service SharedAccess -Force -ErrorAction SilentlyContinue
    }
    Write-Host '--- listeners on the ports this lane binds, before binding ---'
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -in 80, 8080, 8443 } |
        Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize | Out-String | Write-Host
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq 53 } |
        Format-Table LocalAddress, LocalPort, OwningProcess -AutoSize | Out-String | Write-Host

    # ------------------------------------------------------------------
    # THE LAB PEER, AND IT GOES FIRST.
    #
    # It owns the overlay addresses the oracle binds, so starting the oracle
    # first would be a bind to an address that does not exist yet -- which fails
    # and reads as "the oracle is not listening" three functions later.
    #
    # It stays up for the WHOLE run, including across the guest's `taskkill`.
    # The oracle's HTTP and protected-DNS listeners live on these addresses; if
    # the peer tore its adapter down when the guest's session dropped, those
    # sockets would die inside the ARMED window, sentinel continuity would break
    # and the session would grade INCONCLUSIVE instead of PASS.
    # ------------------------------------------------------------------
    $wintunDir = Join-Path $Repo 'build\ci\.cache'
    if (-not (Test-Path (Join-Path $wintunDir 'wintun.dll'))) {
        throw ("the pinned Wintun driver is not staged at $wintunDir\wintun.dll. " +
               "build/ci/fetch-wintun.sh puts it there and the workflow runs it " +
               "before -Action run; the peer cannot create its adapter without it.")
    }
    # ONE SEED PER RUN, generated here and never committed. The guest half is
    # copied into the guest by `ci-windows-killswitch.sh`; the peer half never
    # leaves this host. Both are keys for a lab tunnel and nothing else.
    $guestSeed = Join-Path $RunDir 'guest.json'
    $peerSeed  = Join-Path $RunDir 'peer.json'
    & $peer seed --guest-out $guestSeed --peer-out $peerSeed `
                 --peer-endpoint "$($L1GuestV4):$PeerEndpointPort" | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "twinpeer seed exited $LASTEXITCODE" }
    foreach ($f in @($guestSeed, $peerSeed)) {
        if (-not (Test-Path $f)) { throw "twinpeer seed exited 0 but wrote no $f" }
    }
    $peerOut = Join-Path $RunDir 'twinpeer.out'
    $pids += (Start-Process -FilePath $peer -PassThru -NoNewWindow `
        -ArgumentList @('serve', '--seed', $peerSeed, '--wintun-dll', $wintunDir,
                        '--adapter-name', $PeerAdapter) `
        -RedirectStandardOutput $peerOut `
        -RedirectStandardError  (Join-Path $RunDir 'twinpeer.err')).Id

    # WAITED FOR ON THE PEER'S OWN STDOUT, not slept on. It prints
    # TWINPEER_ADAPTER_READY <luid> once the Wintun adapter exists and then
    # binds its UDP endpoint; the ADDRESSES are this script's to assign, because
    # the peer holds no address plan and the plan lives in one place (above).
    $peerLuid = $null
    $deadline = (Get-Date).AddSeconds(60)
    while (-not $peerLuid -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $hit = Select-String -Path $peerOut -Pattern '^TWINPEER_ADAPTER_READY (\S+)' `
               -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $peerLuid = $hit.Matches[0].Groups[1].Value }
    }
    if (-not $peerLuid) {
        foreach ($f in 'twinpeer.out', 'twinpeer.err') {
            $path = Join-Path $RunDir $f
            Write-Host "---- $f ----"
            if (Test-Path $path) { Get-Content -LiteralPath $path -Tail 40 | Write-Host } else { Write-Host '(absent)' }
        }
        throw "the lab peer never printed TWINPEER_ADAPTER_READY within 60 s; its output is above"
    }
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Get-NetAdapter -Name $PeerAdapter -ErrorAction SilentlyContinue) -and
           (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    $peerNic = Get-NetAdapter -Name $PeerAdapter -ErrorAction SilentlyContinue
    if (-not $peerNic) {
        throw "the peer reported adapter LUID $peerLuid ready, but Windows has no adapter named $PeerAdapter"
    }
    New-NetIPAddress -InterfaceIndex $peerNic.ifIndex -IPAddress $PeerOverlayV4 -PrefixLength 24 | Out-Null
    New-NetIPAddress -InterfaceIndex $peerNic.ifIndex -IPAddress $PeerOverlayV6 -PrefixLength 64 | Out-Null
    foreach ($fam in @('IPv4', 'IPv6')) {
        # The same reason New-Fabric gives for the two lab vNICs, and it is the
        # BASELINE leg that needs it: the guest's beacon arrives on switch A
        # addressed to an address this host holds on THIS adapter, and the
        # reply's source is likewise. Strong host -- the Windows default --
        # drops both, and the SILENCE phase would then pass for a reason that is
        # not the product.
        Set-NetIPInterface -InterfaceIndex $peerNic.ifIndex -AddressFamily $fam `
            -Forwarding Enabled -WeakHostReceive Enabled -WeakHostSend Enabled
    }
    # The TUNNELLED and RESTORED beacons arrive INBOUND on this adapter, so it
    # needs the interface-scoped allow the two lab vNICs already have. Added
    # here rather than in New-Fabric because the adapter does not exist until
    # the peer creates it; the display name is the same, so `-Action destroy`
    # removes it with the rest.
    New-NetFirewallRule -DisplayName $FwRule -Direction Inbound -Action Allow `
        -InterfaceAlias $PeerAdapter | Out-Null
    Write-Host "lab peer up: adapter $PeerAdapter (luid $peerLuid) holds $PeerOverlayV4 and $PeerOverlayV6; endpoint $($L1GuestV4):$PeerEndpointPort"

    # THE ORACLE. The control plane is on LOOPBACK, not on the beacon surface:
    # its own module docs say to bind it to a management address, and here the
    # only client is this host. The guest therefore cannot reach the control
    # plane at all, which is stronger than the guest merely not holding a token.
    # PORT 8080, NOT 80, AND SAID SO IN THE ADVERTISED URL. The first hosted run
    # died with WSAEACCES (10013) binding a listener: on Windows, port 80 is
    # held by HTTP.sys for any process that reserved a URL prefix, and a bind
    # by anyone else is refused rather than shared. Nothing about the criterion
    # depends on the port; the guest beacons at whatever URL the oracle hands
    # the controller. Port 53 has no such owner once ICS is stopped (below).
    $oracleArgs = @(
        'serve', '--control', '127.0.0.1:8443', '--control-token-file', $controlToken,
        # THE HTTP LISTENERS ARE ON THE PEER'S OVERLAY ADDRESSES, and the
        # advertised addresses with them, so the beacon target sits inside the
        # Tier-1 protected scope. See the header. The DNS listeners STAY on
        # switch B: both relays are on this host and forward to them, and
        # nothing the device sends reaches them directly.
        '--http4', "$($PeerOverlayV4):$OraclePort", '--http6', "[$PeerOverlayV6]:$OraclePort",
        '--advertise-port', "$OraclePort",
        '--dns4',  "$($OracleV4):53", '--dns6',  "[$OracleV6]:53",
        '--zone', $Zone, '--advertise-v4', $PeerOverlayV4, '--advertise-v6', $PeerOverlayV6,
        '--sentinel-max-gap-ms', '15000', '--sentinel-token-file', $sentinelToken,
        # The UNPROTECTED resolver, by the address the forwarder presents.
        '--resolver', "$ResolverV4=lab-recursive:u",
        '--resolver', "$ResolverV6=lab-recursive:u",
        # The PROTECTED resolver, likewise by the address its forwarder
        # presents -- which is NOT the address it listens on. The listener is on
        # the peer overlay and reachable only through the tunnel; the source is
        # on switch B, so the two DNS identities are disjoint and `:p` and `:u`
        # can never collide.
        #
        # This is a LAB action standing in for a product resolver that does not
        # exist: `enforce.rs:265-289` assembles `denied_dns_policy()` with empty
        # stub addresses, so nothing in TwinVPN binds port 53. The product's job
        # in this criterion is to BLOCK the resolver once armed, not to
        # configure it, and `dns_protected_resolver` in the evidence says so.
        '--resolver', "$ProtResolverSrcV4=twinvpn-dns:p",
        '--resolver', "$ProtResolverSrcV6=twinvpn-dns:p"
    )
    $pids += (Start-Process -FilePath $oracle -ArgumentList $oracleArgs -PassThru -NoNewWindow `
        -RedirectStandardOutput (Join-Path $RunDir 'oracle.out') `
        -RedirectStandardError  (Join-Path $RunDir 'oracle.err')).Id

    # THE RESOLVER, one stateless relay per family. It must not cache, retry or
    # health-check: any of those manufactures a DNS arrival during SILENCE,
    # which the oracle records as a leak against the product.
    #
    # FOUR of them now, not two: an unprotected pair on switch B, which is where
    # the guest's stub points at BASELINE, and a PROTECTED pair listening on the
    # peer's overlay addresses, which the guest can reach only through the
    # tunnel. `--source` is a separate column because the protected pair must
    # present a switch-B address the oracle maps `twinvpn-dns:p` rather than the
    # overlay address it listens on.
    $fwd = Join-Path $Repo 'build\ci\dns-forward.py'
    foreach ($f in @(@($ResolverV4,    $OracleV4, 'v4', $ResolverV4),
                     @($ResolverV6,    $OracleV6, 'v6', $ResolverV6),
                     @($PeerOverlayV4, $OracleV4, 'p4', $ProtResolverSrcV4),
                     @($PeerOverlayV6, $OracleV6, 'p6', $ProtResolverSrcV6))) {
        # By the address, not by a tag: an IPv6 literal is the one that carries
        # a colon, and the tag is now only the log file's name.
        $isV6     = $f[0].Contains(':')
        $listen   = if ($isV6) { "[$($f[0])]:53" } else { "$($f[0]):53" }
        $upstream = if ($isV6) { "[$($f[1])]:53" } else { "$($f[1]):53" }
        $pids += (Start-Process -FilePath 'python' `
            -ArgumentList @($fwd, '--listen', $listen, '--upstream', $upstream, '--source', $f[3]) `
            -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $RunDir "forwarder-$($f[2]).out") `
            -RedirectStandardError  (Join-Path $RunDir "forwarder-$($f[2]).err")).Id
    }

    Start-Sleep -Seconds 3
    if (-not (Test-NetConnection -ComputerName $PeerOverlayV4 -Port $OraclePort -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        Write-Host '---- oracle.err ----'; Get-Content -LiteralPath (Join-Path $RunDir 'oracle.err') -ErrorAction SilentlyContinue | Write-Host
        Write-Host '---- twinpeer.err ----'; Get-Content -LiteralPath (Join-Path $RunDir 'twinpeer.err') -ErrorAction SilentlyContinue | Write-Host
        throw "the oracle is not listening on $($PeerOverlayV4):$OraclePort. See $RunDir\oracle.err and $RunDir\twinpeer.err."
    }

    # THE SENTINEL, from the SECOND identities on switch B. `--source` pins them
    # with `curl --interface`, so the addresses the oracle records are these
    # rather than whichever the routing table picked -- which is the entire
    # independence claim on a multi-homed host.
    $bash = 'C:\Program Files\Git\bin\bash.exe'
    $sentinelLog = Join-Path $RunDir 'sentinel.log'
    $cmd = ("cd '$(ConvertTo-BashPath $Repo)' && build/ci/leak-probe.sh sentinel " +
            "--token-file '$(ConvertTo-BashPath $sentinelToken)' " +
            "--beacon-v4 'http://$($PeerOverlayV4):$OraclePort/b' --beacon-v6 'http://[$PeerOverlayV6]:$OraclePort/b' " +
            "--zone $Zone --source $SentinelV4 --source $SentinelV6 " +
            "--dns-server $ResolverV4 --interval-ms 2000")
    # THROUGH A SCRIPT FILE, NOT `-lc "<command>"`. Start-Process joins its
    # argument list with spaces and quotes nothing, so a command containing
    # spaces reached bash as `-lc cd` plus stray words: bash ran `cd`, exited
    # zero, and both logs stayed empty for two runs. A file has no quoting.
    $sentinelScript = Join-Path $RunDir 'sentinel.sh'
    Set-Content -LiteralPath $sentinelScript -Value ("#!/usr/bin/env bash`nset -euo pipefail`n" + $cmd + "`n") -NoNewline
    $pids += (Start-Process -FilePath $bash -ArgumentList @('--login', (ConvertTo-BashPath $sentinelScript)) -PassThru -NoNewWindow `
        -RedirectStandardOutput $sentinelLog `
        -RedirectStandardError  (Join-Path $RunDir 'sentinel.err')).Id
    $pids -join "`n" | Set-Content -LiteralPath $PidFile

    # MEASURED from what the sentinel printed, not from what we passed it.
    # Polled rather than slept: git-bash start-up on a cold runner takes longer
    # than the three seconds the first run allowed, and a fixed sleep turned
    # that into "Cannot index into a null array" with the sentinel's own error
    # left unread in a directory nobody uploaded.
    $identity = $null
    $deadline = (Get-Date).AddSeconds(45)
    while (-not $identity -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $hit = Select-String -Path $sentinelLog -Pattern '^TWINVPN_SENTINEL_EGRESS_IDENTITY (.+)$' `
               -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($hit) { $identity = $hit.Matches[0].Groups[1].Value }
    }
    if (-not $identity) {
        foreach ($f in 'sentinel.log', 'sentinel.err', 'oracle.err', 'twinpeer.err',
                       'forwarder-v4.err', 'forwarder-v6.err', 'forwarder-p4.err', 'forwarder-p6.err') {
            $path = Join-Path $RunDir $f
            Write-Host "---- $f ----"
            if (Test-Path $path) { Get-Content -LiteralPath $path -Tail 40 | Write-Host } else { Write-Host '(absent)' }
        }
        throw "the sentinel never printed its egress identity within 45 s; its output is above"
    }
    Write-Host "observers up; sentinel presents $identity"
    return @{ ControlToken = (Get-Content -Raw $controlToken).Trim(); SentinelIdentity = $identity }
}

function Stop-Observers {
    if (-not (Test-Path $PidFile)) { return }
    foreach ($line in Get-Content $PidFile) {
        if ($line -match '^\d+$') { Stop-Process -Id ([int]$line) -Force -ErrorAction SilentlyContinue }
    }
    # By name as well as by pid, in case one was restarted by hand. The peer
    # holds a Wintun adapter, which goes away with the process that created it.
    foreach ($n in 'twinoracle', 'twinpeer') {
        Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
}

function New-Guest {
    if (-not (Test-Path $BaseVhd)) { throw "no base image at $BaseVhd; run -Action build-image first." }
    New-Item -ItemType Directory -Path $RunDir -Force | Out-Null
    if (Test-Path $DiffVhd) { Remove-Item -LiteralPath $DiffVhd -Force }
    New-VHD -Path $DiffVhd -ParentPath $BaseVhd -Differencing | Out-Null

    # THE UNATTEND GOES IN THE DISPOSABLE DISK ONLY, never in the base image:
    # it carries the guest administrator's password in plain text, which is what
    # Windows Setup requires. See scripts/twinvpn-l1-unattend.xml.
    $answer = (Get-Content -Raw (Join-Path $Here 'twinvpn-l1-unattend.xml')).
                Replace('%TWINVPN_GUEST_USER%', $GuestUser).
                Replace('%TWINVPN_GUEST_PASSWORD%', $env:TWINVPN_GUEST_PASSWORD)
    if ($answer -match '%TWINVPN_') {
        throw 'the unattend template still contains a placeholder; the guest would boot with a literal marker as its password and never accept a session'
    }
    # WELL-FORMED BEFORE IT IS WRITTEN. Windows Setup does not report a broken
    # answer file anywhere this host can see: it skips it, leaves the guest in
    # OOBE with no local account, and the only symptom is PowerShell Direct
    # timing out twenty minutes later. A `--` inside an XML comment is enough to
    # cause that, and this line is what turns it into an immediate refusal.
    $null = [xml] $answer
    $disk = Mount-VHD -Path $DiffVhd -Passthru | Get-Disk
    try {
        $part = Get-Partition -DiskNumber $disk.Number |
                Where-Object { $_.Type -eq 'Basic' } | Select-Object -Last 1
        if (-not $part.DriveLetter) { Set-Partition -InputObject $part -NewDriveLetter 'U' | Out-Null }
        $letter = (Get-Partition -DiskNumber $disk.Number -PartitionNumber $part.PartitionNumber).DriveLetter
        $panther = "$($letter):\Windows\Panther"
        New-Item -ItemType Directory -Path $panther -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $panther 'unattend.xml') -Encoding UTF8 -Value $answer
    }
    finally { Dismount-VHD -Path $DiffVhd -ErrorAction SilentlyContinue }

    New-VM -Name $VmName -MemoryStartupBytes ($MemoryGB * 1GB) -VHDPath $DiffVhd `
           -Generation 2 -SwitchName $SwGuest | Out-Null
    Set-VMProcessor -VMName $VmName -Count $Cpus
    Set-VMMemory   -VMName $VmName -DynamicMemoryEnabled $false
    Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false -AutomaticStopAction TurnOff
    Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows
    try {
        Set-VMKeyProtector -VMName $VmName -NewLocalKeyProtector
        Enable-VMTPM -VMName $VmName
        Write-Host 'vTPM enabled with a local key protector'
    } catch {
        # STATED, not silent. A guest without a vTPM is still a valid host for
        # this criterion -- WFP does not need one -- but the evidence should not
        # imply the DUT resembled a shipping machine more than it did.
        Write-Warning "this host refused a vTPM ($($_.Exception.Message)); the guest boots without one"
    }
    # For Copy-Item over the VMBus session.
    Enable-VMIntegrationService -VMName $VmName -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
    Start-VM -Name $VmName

    Write-Host 'waiting for PowerShell Direct'
    $deadline = (Get-Date).AddMinutes($BootTimeoutMinutes)
    while ((Get-Date) -lt $deadline) {
        try { $s = New-GuestSession; Remove-PSSession $s; Write-Host 'guest accepted a session'; return }
        catch { Start-Sleep -Seconds 15 }
    }
    throw ("the guest never accepted a PowerShell Direct session within " +
           "$BootTimeoutMinutes minutes. It needs a configured user profile, " +
           "which the unattend file's AutoLogon creates on first boot; a guest " +
           "stuck in OOBE looks exactly like this.")
}

function Remove-Guest {
    $vm = Get-VM -Name $VmName -ErrorAction SilentlyContinue
    if ($vm) {
        Write-Host "destroying guest $VmName"
        if ($vm.State -ne 'Off') { Stop-VM -Name $VmName -TurnOff -Force }
        $disks = (Get-VMHardDiskDrive -VMName $VmName).Path
        Remove-VM -Name $VmName -Force
        foreach ($d in $disks) { if (Test-Path $d) { Remove-Item -LiteralPath $d -Force } }
    }
    if (Test-Path $DiffVhd) { Remove-Item -LiteralPath $DiffVhd -Force -ErrorAction SilentlyContinue }
}

Assert-Elevated

switch ($Action) {

    'preflight' {
        Assert-Hypervisor
        $free = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 1)
        Write-Host "C: has $free GB free"
        if ($free -lt 25) { throw "C: has $free GB free; the image, the differencing disk and a cargo target need more." }
        foreach ($t in @('C:\Program Files\Git\bin\bash.exe')) {
            if (-not (Test-Path $t)) { throw "$t is missing; the lane and the sentinel are bash." }
        }
        foreach ($c in @('cargo', 'python', 'curl.exe')) {
            if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not on PATH." }
        }
        Write-Host 'preflight: hypervisor, disk, bash, cargo, python and curl are all present'
    }

    # The 4.8 GB ISO download, started in the background so the cargo builds
    # run beside it; `build-image` waits for it. See twinvpn-l1-image.ps1.
    'prefetch-iso' {
        & (Join-Path $Here 'twinvpn-l1-image.ps1') -VhdPath $BaseVhd -WorkDir $VmRoot -Prefetch
    }

    'build-image' {
        Assert-Hypervisor
        & (Join-Path $Here 'twinvpn-l1-image.ps1') -VhdPath $BaseVhd -WorkDir $VmRoot
    }

    'run' {
        foreach ($p in 'RepoPath', 'EvidenceOut') {
            if (-not $PSBoundParameters.ContainsKey($p)) { throw "-$p is required for -Action run." }
        }
        Assert-Hypervisor
        $env:TWINVPN_GUEST_PASSWORD = (New-Secret 18) + '!aA1'
        try {
            New-Fabric
            $obs = Start-Observers $RepoPath
            New-Guest

            $bash = 'C:\Program Files\Git\bin\bash.exe'
            $env:TWINVPN_ORACLE_URL             = 'http://127.0.0.1:8443'
            $env:TWINVPN_ORACLE_TOKEN           = $obs.ControlToken
            $env:TWINVPN_ORACLE_CONTROL_BY      = 'controller'
            $env:TWINVPN_ORACLE_TOPOLOGY        = 'in-box'
            $env:TWINVPN_ORACLE_ZONE_NAME       = $Zone
            $env:TWINVPN_SENTINEL_HOST          = "l1-runner:$($env:COMPUTERNAME) (in-box, same host as the oracle)"
            $env:TWINVPN_SENTINEL_EGRESS_IDENTITY = $obs.SentinelIdentity
            $env:TWINVPN_L1_CONTROLLER          = '1'
            $env:TWINVPN_GUEST_VM               = $VmName
            $env:TWINVPN_L1_RUNDIR              = $RunDir

            Write-Host 'running the kill-switch sequence from this host against the guest'
            $repoSh = ConvertTo-BashPath $RepoPath
            # A script file, for the reason Start-Observers gives.
            $sequenceScript = Join-Path $RunDir 'sequence.sh'
            Set-Content -LiteralPath $sequenceScript `
                -Value "#!/usr/bin/env bash`nset -euo pipefail`ncd '$repoSh' && build/ci/ci-windows-killswitch.sh`n" -NoNewline
            $p = Start-Process -FilePath $bash -PassThru -NoNewWindow `
                 -ArgumentList @('--login', (ConvertTo-BashPath $sequenceScript))
            if (-not $p.WaitForExit($RunTimeoutMinutes * 60 * 1000)) {
                $p.Kill(); throw "the kill-switch sequence did not finish within $RunTimeoutMinutes minutes"
            }
            $exit = $p.ExitCode

            if ($exit -ne 0) {
                throw ("the kill-switch sequence exited $exit. The evidence and logs were " +
                       "still written; read build/ci/evidence/windows-killswitch.json for the " +
                       "measured state and build/ci/logs/windows/ for what the oracle saw.")
            }
            Write-Host 'kill-switch sequence completed'
        }
        finally {
            # The observers' output FIRST, on every path: the diagnostics
            # artifact uploads build/ci/logs/windows/**, and a failure before
            # the sequence ran used to leave every log in the run directory.
            try {
                $logsOut = Join-Path (Split-Path $EvidenceOut -Parent) 'logs\windows'
                New-Item -ItemType Directory -Path $logsOut -Force | Out-Null
                Copy-Item -Path (Join-Path $RunDir '*.out'), (Join-Path $RunDir '*.err'), `
                                (Join-Path $RunDir '*.log') `
                          -Destination $logsOut -Force -ErrorAction SilentlyContinue
                # What L1's firewall held and dropped, for the reachability diagnosis.
                Get-NetFirewallRule -DisplayName $FwRule -ErrorAction SilentlyContinue |
                    ForEach-Object { $_ | Get-NetFirewallPortFilter; $_ | Get-NetFirewallAddressFilter; $_ | Get-NetFirewallInterfaceFilter } |
                    Out-String | Set-Content -LiteralPath (Join-Path $logsOut 'l1-firewall-rules.txt')
                Copy-Item -Path "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" `
                          -Destination (Join-Path $logsOut 'l1-pfirewall.log') -Force -ErrorAction SilentlyContinue
                Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                    Where-Object { $_.LocalPort -in $OraclePort, 8443 } | Out-String |
                    Set-Content -LiteralPath (Join-Path $logsOut 'l1-listeners.txt')
            } catch { Write-Host "could not copy the run directory's logs: $_" }
            # On every path including a throw and a cancellation. A guest left
            # running holds a differencing disk and, having installed persistent
            # WFP filters, is a machine nobody can reach over the network.
            Remove-Guest
            Stop-Observers
            Remove-Fabric
        }
    }

    'destroy' {
        Remove-Guest
        Stop-Observers
        Remove-Fabric
    }

    'guest-exec' {
        if (-not $Step) { throw '-Step is required for -Action guest-exec.' }
        $s = New-GuestSession
        try {
            Invoke-Command -Session $s -FilePath (Join-Path $Here 'twinvpn-l1-guest.ps1') `
                           -ArgumentList $Step, $Arg1, $Arg2
        }
        finally { Remove-PSSession $s -ErrorAction SilentlyContinue }
    }

    'push' {
        $s = New-GuestSession
        try { Copy-Item -Path $LocalPath -Destination $RemotePath -ToSession $s -Recurse -Force }
        finally { Remove-PSSession $s -ErrorAction SilentlyContinue }
    }

    'fetch' {
        $s = New-GuestSession
        try {
            if (Invoke-Command -Session $s -ArgumentList $RemotePath -ScriptBlock { param($p) Test-Path $p }) {
                Copy-Item -Path $RemotePath -Destination $LocalPath -FromSession $s -Force
            } else { throw "the guest has no file at $RemotePath" }
        }
        finally { Remove-PSSession $s -ErrorAction SilentlyContinue }
    }
}
