#!/usr/bin/env bash
# Kill switch check with the VPN OFF, run from WSL: the WSL Allow rule is gone, and neither WSL nor Windows reaches
# Anthropic directly, while ya.ru still goes out. Safe: every probe is a TCP SYN with TTL=1, which dies at the first
# router, so nothing reaches Anthropic even if the block has failed.
#   bash claude-killswitch-vpn-off-test.sh [tunnel IP, default 172.19.0.1]
set -u
TUN_IP=${1:-172.19.0.1}
ANTHROPIC='160.79.104.10 34.36.57.103 34.120.108.227 35.190.46.17'  # api.anthropic.com, claude.ai + the CDN IPs in the rule
CONTROL=77.88.55.242                                                   # ya.ru: must still go out
PS=/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe
fail=0

winps() {
    # Progress records would come out as CLIXML.
    "$PS" -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand "$(printf '%s\n%s' \
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; \$ProgressPreference = 'SilentlyContinue'" "$1" |
        iconv -t UTF-16LE | base64 -w0)" 2>&1 | tr -d '\r'
}
allow_ips() { winps "(Get-NetFirewallHyperVRule -Name 'ClaudeKillSwitch-WSL-Tunnel' -ErrorAction SilentlyContinue).LocalAddresses" | xargs; }
# Blocked: no answer at all. Not blocked: the router answers that TTL ran out.
probe() { sudo timeout 15 traceroute -n -T -p 443 -f 1 -m 1 -q 2 -w 2 "$1" 2>&1 | tail -1; }

if ip -4 -br addr | grep -qw "$TUN_IP"; then echo "Tunnel $TUN_IP is still up: turn the VPN off first"; exit 2; fi
sudo true || exit 2  # asks for a password, if one is needed, before the timed probes

echo "== WSL Allow rule (the task drops it on network event 10001)"
for _ in $(seq 15); do [ -z "$(allow_ips)" ] && break; sleep 2; done
left=$(allow_ips)
if [ -z "$left" ]; then echo "OK    removed"
else echo "WARN  still allows $left after 30 s: the 10001 trigger did not fire (WSL stays blocked by source IP)"; fi

echo "== WSL: $(ip route get 160.79.104.10 | head -1)"
for ip in $ANTHROPIC; do
    r=$(probe "$ip")
    if [[ $r == *'* *'* ]]; then echo "OK    $ip blocked"; else echo "FAIL  $ip NOT blocked:${r#*1}"; fail=1; fi
done
r=$(probe "$CONTROL")
if [[ $r == *'* *'* ]]; then echo "FAIL  control $CONTROL got no answer either: the WSL probes prove nothing"; fail=1
else echo "OK    control $CONTROL went out:${r#*1}"; fi

echo "== Windows (blocked = refused 10013 at once; went out = timeout)"
code=$(cat <<'EOF'
function Probe([string]$ip) {
    $s = New-Object Net.Sockets.Socket ([Net.Sockets.AddressFamily]::InterNetwork), ([Net.Sockets.SocketType]::Stream), ([Net.Sockets.ProtocolType]::Tcp)
    $s.Ttl = 1
    try {
        $r = $s.BeginConnect($ip, 443, $null, $null)
        if (-not $r.AsyncWaitHandle.WaitOne(4000)) { return 'timeout' }
        $s.EndConnect($r); 'connected'
    } catch {
        $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }
        if ($e.ErrorCode -eq 10013) { 'refused 10013' } else { "error: $($e.Message)" }
    } finally { $s.Close() }
}
foreach ($ip in @('__ANTHROPIC__' -split ' ') + '__CONTROL__') {
    $via = (Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select-Object -Last 1).InterfaceAlias
    $res = Probe $ip
    $ok = if ($ip -eq '__CONTROL__') { $res -eq 'timeout' } else { $res -eq 'refused 10013' }
    '{0,-5} {1,-15} via {2}: {3}' -f $(if ($ok) { 'OK' } else { 'FAIL' }), $ip, $via, $res
}
'== Rules and the last task run'
Get-NetFirewallHyperVRule -Name 'ClaudeKillSwitch-WSL-*' |
    Format-Table Name, Action, Enabled, RulePriority, LocalAddresses -AutoSize | Out-String -Width 200
$log = Join-Path $env:ProgramFiles 'ClaudeKillSwitch\last-run.log'
"last-run.log, written $((Get-Item $log).LastWriteTime.ToString('HH:mm:ss')):"
Get-Content $log
EOF
)
code=${code//__ANTHROPIC__/$ANTHROPIC}
win=$(winps "${code//__CONTROL__/$CONTROL}")
echo "$win" | grep -v '^\s*$'
grep -q '^FAIL' <<<"$win" && fail=1

if ((fail)); then echo "== FAILED"; else echo "== PASSED: turn the VPN back on"; fi
exit $fail
