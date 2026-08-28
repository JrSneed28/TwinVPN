# `shells/windows/packaging`

**Owner:** `desktop-windows`.

| File | What |
|---|---|
| `TwinVPN.wxs` | the WiX/MSI definition — the service, the CLI, WinTun, the store ACL, PS-12a's groups, and PS-21's uninstall order |
| `boot-filters.md` | how the installer applies the **KS-19 boot artifact**, and the one thing a BOOTTIME filter cannot do |
| `signing.md` | the Authenticode/EV signing requirements, as documented steps |

The Linux counterpart is [`shells/linux/packaging/`](../../linux/packaging/),
where the same three concerns are `twinvpnd.service`,
`twinvpn-killswitch.service` + `killswitch.nft`, and (for the third) nothing —
Linux packages are signed by the distribution.

---

## None of this has been built

No WiX toolset has been run against `TwinVPN.wxs`. No `.msi` has ever existed.
No certificate has been obtained and nothing has been signed. Nothing described
here has been installed on any machine.

These files were written on a Linux host, where `candle.exe`, `light.exe` and
`signtool.exe` do not run. The only property that has been checked is that
`TwinVPN.wxs` is **well-formed XML** — not that it compiles under WiX, not that
its custom actions link, not that Windows Installer accepts its sequencing.

Three of the components reference binaries this workspace does not build at all:
`twinvpn-unblock.exe` (ADR-0016 O13), `twinvpn-restore.exe` (ADR-0011 DN-20) and
`twinvpn-bootfilters.dll` (the KS-19 custom action). They are declared so the
layout, the ACLs and the uninstall order are reviewable against the ADRs now
rather than after somebody writes them. A build will fail at `light.exe` with a
missing file — loudly, which is the correct direction.

`shells/windows/README.md` §7 is the numbered list of what is missing and why.
