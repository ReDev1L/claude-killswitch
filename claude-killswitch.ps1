# Kill switch for Anthropic: traffic to Anthropic's addresses may leave only through a VPN tunnel.
# One outbound block rule for every program, on every IP interface except the tunnels and loopback.
# Tunnels: AmneziaVPN (WireGuard) and Happ's TUN modes ('happ-xray' / 'happ-default-tun' in 4.3+, sing-box 'happ-tun'
# before it, tun2proxy 'tun2'). Both route these
# addresses into the tunnel, so with a VPN up the rule never matches. With none up (or for an address the VPN
# sends direct), the connection fails instead of going out directly. That includes Happ's own direct outbound:
# xray / sing-box connecting to Anthropic from Ethernet is blocked too.
# Other traffic is untouched and follows the VPN client's own rules.
# Windows Firewall cannot match domains, and the rule is bound to concrete interfaces. -Install adds a SYSTEM
# task that re-syncs both whenever a network connects (new adapter, Wi-Fi, VPN) and daily. The task runs a copy
# in Program Files (admin-only writable). Re-run -Install after editing this file.
# WSL traffic does not pass the host rule: Hyper-V firewall filters it, and that has no interface condition.
# In mirrored networking a WSL packet carries the IP of the Windows adapter it leaves through, so WSL gets a
# Hyper-V rule pair instead: block Anthropic, but allow it from the tunnels' own IPs at a higher priority.
# A tunnel with a new name or IP stays blocked for WSL until the next sync: this fails closed.
#   .\claude-killswitch.ps1 -Install   # copy to Program Files, register the refresh task, sync now (admin)
#   .\claude-killswitch.ps1            # sync the rules once (admin)
#   .\claude-killswitch.ps1 -Status    # show coverage, live routes and the task's last run (no admin)
#   .\claude-killswitch.ps1 -Remove    # delete the rules, the task and the installed copy (admin)
# Windows PowerShell 5.1 compatible: the task runs under it.
param(
    [switch]$Status,
    [switch]$Install,
    [switch]$Remove,
    # Tunnel interface aliases, wildcards allowed. Happ renames its TUN between versions, hence 'happ-*'.
    [string[]]$VpnAlias = @('AmneziaVPN', 'happ-*', 'tun2*')
)

$RuleGroup = 'Claude kill switch'
$TaskName = 'Claude kill switch refresh'
$InstallDir = Join-Path $env:ProgramFiles 'ClaudeKillSwitch'
$InstallPath = Join-Path $InstallDir 'claude-killswitch.ps1'
$LogPath = Join-Path $InstallDir 'last-run.log'
# Anthropic's own network: api.anthropic.com, claude.ai, console, docs, code.claude.com.
$Ranges = '160.79.104.0/21', '2607:6bc0::/48'
# Anthropic hosts served from Google Cloud load balancers outside that network.
$CdnHosts = 'a-cdn.anthropic.com', 'assets.claude.ai', 'downloads.claude.ai'
# WSL's Hyper-V firewall rules. A lower RulePriority is evaluated first, so the tunnel Allow (10) beats the Block (20).
$WslCreator = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'
$WslBlockRule = 'ClaudeKillSwitch-WSL-Block'
$WslTunnelRule = 'ClaudeKillSwitch-WSL-Tunnel'
# Hyper-V firewall and its cmdlets exist from Windows 11 22H2.
$HyperV = [bool](Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue)

function Test-Tunnel([string]$Alias) { [bool]($VpnAlias | Where-Object { $Alias -like $_ }) }

$guarded = Get-NetIPInterface |
    Where-Object { -not (Test-Tunnel $_.InterfaceAlias) -and $_.InterfaceAlias -notlike 'Loopback*' } |
    Select-Object -ExpandProperty InterfaceAlias -Unique
# Mirrored WSL traffic through a tunnel has the tunnel's IP as its source. Link-local IPs are no tunnel config
# (APIPA on an unconfigured adapter; IPv6 ones also carry a %scope suffix).
$tunnelIps = @(Get-NetIPAddress |
    Where-Object { (Test-Tunnel $_.InterfaceAlias) -and $_.IPAddress -notlike 'fe80:*' -and $_.IPAddress -notlike '169.254.*' } |
    Select-Object -ExpandProperty IPAddress -Unique)

$unresolved = @()
$cdnIps = foreach ($h in $CdnHosts) {
    $ips = (Resolve-DnsName $h -ErrorAction SilentlyContinue | Where-Object { $_.Type -in 'A', 'AAAA' }).IPAddress
    if (-not $ips) { $unresolved += $h }
    $ips
}
$cdnIps = @($cdnIps | Select-Object -Unique)

if ($Status) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = $task | Get-ScheduledTaskInfo
        "Auto-refresh : $($task.State), last run $($info.LastRunTime) (result $($info.LastTaskResult))"
    } elseif (Test-Path $InstallPath) {
        # A SYSTEM task is hidden from non-admins; its log is not.
        "Auto-refresh : installed, last run $((Get-Item $LogPath -ErrorAction SilentlyContinue).LastWriteTime)"
    } else { Write-Warning "No '$TaskName' task: the rule is not refreshed automatically" }

    if (-not $HyperV) {
        Write-Warning 'No Hyper-V firewall (needs Windows 11 22H2+): Anthropic traffic from WSL is not restricted'
    } elseif (-not ($wslBlock = Get-NetFirewallHyperVRule -Name $WslBlockRule -ErrorAction SilentlyContinue)) {
        Write-Warning "No '$WslBlockRule' rule: Anthropic traffic from WSL is not restricted"
    } else {
        if ($wslBlock.Enabled -ne 'True' -or $wslBlock.Action -ne 'Block') {
            Write-Warning "'$WslBlockRule' is disabled or not a Block: Anthropic traffic from WSL is not restricted. Re-run as admin."
        }
        $wslTunnel = Get-NetFirewallHyperVRule -Name $WslTunnelRule -ErrorAction SilentlyContinue
        $wslAllowed = if ($wslTunnel) { @($wslTunnel.LocalAddresses) } else { @() }
        "WSL allowed  : from $(if ($wslAllowed) { $wslAllowed -join ', ' } else { 'nowhere (no tunnel at last sync)' })"
        $stale = @($tunnelIps | Where-Object { $_ -notin $wslAllowed })
        if ($stale) { Write-Warning "Tunnel IPs not allowed for WSL: $($stale -join ', '). Re-run as admin." }
        $orphan = @($wslAllowed | Where-Object { $_ -notin $tunnelIps })
        if ($orphan) { Write-Warning "WSL allowed from IPs no tunnel has now: $($orphan -join ', '). Re-run as admin." }
        if ((Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -Name $WslCreator).Enabled -ne 'True') {
            Write-Warning 'Hyper-V firewall is off for WSL: the WSL rules do nothing'
        }
        if (-not (@(Get-Content "$env:USERPROFILE\.wslconfig" -ErrorAction SilentlyContinue) -match '^\s*networkingMode\s*=\s*mirrored')) {
            Write-Warning 'WSL networking is not mirrored: its traffic does not carry the tunnel IPs the WSL rules allow'
        }
    }

    $rule = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
    if (-not $rule) { Write-Warning "No '$RuleGroup' rule: Anthropic traffic is not restricted"; return }
    $covered = @(($rule | Get-NetFirewallInterfaceFilter).InterfaceAlias)
    $blocked = @(($rule | Get-NetFirewallAddressFilter).RemoteAddress)
    "Enabled      : $($rule.Enabled)"
    "Blocked on   : $($covered -join ', ')"
    "Addresses    : $($blocked -join ', ')"
    @('160.79.104.10') + $cdnIps | ForEach-Object {
        $route = (Find-NetRoute -RemoteIPAddress $_ | Select-Object -Last 1).InterfaceAlias
        [pscustomobject]@{ Address = $_; Route = $route; Works = if (Test-Tunnel $route) { 'yes' } else { 'NO: blocked' } }
    } | Format-Table -AutoSize | Out-String
    $missing = @($guarded | Where-Object { $_ -notin $covered })
    if ($missing) { Write-Warning "Interfaces not covered: $($missing -join ', '). Re-run as admin." }
    $moved = @($cdnIps | Where-Object { $_ -notin $blocked })
    if ($moved) { Write-Warning "CDN IPs changed ($($moved -join ', ')). Re-run as admin." }
    return
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run from an elevated PowerShell (or use -Status).' }

if ($Remove) {
    Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($HyperV) {
        Get-NetFirewallHyperVRule -Name $WslBlockRule, $WslTunnelRule -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    "Removed '$RuleGroup' rules (host and WSL), task and $InstallDir"
    return
}

if ($Install) {
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    if ($PSCommandPath -ne $InstallPath) { Copy-Item $PSCommandPath $InstallPath -Force }

    $aliases = ($VpnAlias | ForEach-Object { "'$_'" }) -join ','
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"& '$InstallPath' -VpnAlias $aliases *> '$LogPath'`""
    # NetworkProfile 10000 = a network connected: new adapter, Wi-Fi join, VPN up. 10001 = disconnected: a VPN going
    # down must drop its IP from the WSL Allow.
    $eventClass = Get-CimClass -Namespace root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskEventTrigger
    $onNetwork = New-CimInstance -CimClass $eventClass -ClientOnly -Property @{
        Enabled      = $true
        Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">' +
                       '<Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000 or EventID=10001)]]</Select>' +
                       '</Query></QueryList>'
    }
    $triggers = $onNetwork, (New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Daily -At '12:00')
    # Queue, not IgnoreNew: an event during a run may mean an adapter the running sync has not seen.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances Queue -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers -Settings $settings `
        -Principal $principal -Description "Keeps the '$RuleGroup' firewall rules in sync with network adapters" -Force | Out-Null
    "Installed $InstallPath and task '$TaskName'"
}

# Update in place so a refresh never leaves a window without the rule.
$rule = Get-NetFirewallRule -Group $RuleGroup -ErrorAction SilentlyContinue
if ($unresolved) { Write-Warning "Cannot resolve $($unresolved -join ', ')" }
if (-not $rule) {
    New-NetFirewallRule -DisplayName "$RuleGroup (Anthropic)" -Group $RuleGroup `
        -Direction Outbound -Action Block -Profile Any -RemoteAddress (@($Ranges) + $cdnIps) -InterfaceAlias $guarded `
        -Description "Anthropic traffic only via $($VpnAlias -join ', ')" | Out-Null
    "Created rule on: $($guarded -join ', ')"
} elseif ($unresolved) {
    # DNS is down (e.g. offline): keep the last known CDN IPs rather than dropping them from the rule.
    $rule | Set-NetFirewallRule -InterfaceAlias $guarded
    "$(Get-Date -Format s) synced interfaces only: $($guarded -join ', ')"
} else {
    $rule | Set-NetFirewallRule -InterfaceAlias $guarded -RemoteAddress (@($Ranges) + $cdnIps)
    "$(Get-Date -Format s) synced: $($guarded -join ', ') / $((@($Ranges) + $cdnIps) -join ', ')"
}

if (-not $HyperV) { Write-Warning 'No Hyper-V firewall: WSL rules skipped'; return }
# A failed WSL rule change must fail the task and keep the success line out of the log.
$ErrorActionPreference = 'Stop'
$wslBlock = Get-NetFirewallHyperVRule -Name $WslBlockRule -ErrorAction SilentlyContinue
# Offline: keep the last known CDN IPs, as for the host rule.
$wslRemote = if ($unresolved -and $wslBlock) { @($wslBlock.RemoteAddresses) } else { @($Ranges) + $cdnIps }
# Every sync re-applies all conditions, so a rule someone disabled or reprioritised is put back.
$common = @{ VMCreatorId = $WslCreator; Direction = 'Outbound'; Enabled = 'True'; Profiles = 'Any'; RemoteAddresses = $wslRemote }
# The Allow goes first, so neither a first install nor a CDN IP change blocks tunnel traffic even briefly.
if (-not $tunnelIps) {
    Get-NetFirewallHyperVRule -Name $WslTunnelRule -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule
} elseif (Get-NetFirewallHyperVRule -Name $WslTunnelRule -ErrorAction SilentlyContinue) {
    Set-NetFirewallHyperVRule -Name $WslTunnelRule -Action Allow -RulePriority 10 -LocalAddresses $tunnelIps @common
} else {
    New-NetFirewallHyperVRule -Name $WslTunnelRule -DisplayName "$RuleGroup (WSL via tunnel)" `
        -Action Allow -RulePriority 10 -LocalAddresses $tunnelIps @common | Out-Null
}
if ($wslBlock) {
    Set-NetFirewallHyperVRule -Name $WslBlockRule -Action Block -RulePriority 20 -LocalAddresses Any @common
} else {
    New-NetFirewallHyperVRule -Name $WslBlockRule -DisplayName "$RuleGroup (WSL)" `
        -Action Block -RulePriority 20 -LocalAddresses Any @common | Out-Null
}
"WSL: Anthropic only from $(if ($tunnelIps) { $tunnelIps -join ', ' } else { 'nowhere (no tunnel up)' })"
