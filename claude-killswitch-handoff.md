# Контекст: kill switch для Anthropic на Windows и в WSL (запросы к Anthropic только через VPN)

## Задача (согласовано с пользователем)
- Все запросы к Anthropic (Claude Code, claude.ai в браузере, любые программы) должны идти ТОЛЬКО через VPN-туннель. Если туннеля нет, соединение должно падать, а не идти напрямую.
- Остальной трафик (в том числе прочие запросы claude.exe: WebFetch, MCP, git) НЕ трогать: он идёт по правилам VPN-клиента (split tunnel).
- Как пришли к решению:
  1) Сначала агент начал делать блокировку по IP Anthropic. Пользователь остановил: "я не хочу блокировать IP, я хочу блокировать сеть для claude, если он обращается вне VPN".
  2) Сделали блокировку claude.exe на всех интерфейсах, кроме VPN. Побочный эффект: при split tunnel Claude не мог открыть сайты вне VPN-списка (WebFetch ya.ru падал). Пользователь попросил удалить правило и уточнил: "все запросы к anthropic только через VPN, а остальные — в зависимости от правил VPN клиента".
  3) Итог: блокируются адреса Anthropic, но ТОЛЬКО на интерфейсах вне туннеля. Через VPN Anthropic доступен, остальной трафик не затронут. Иначе это требование не выразить: брандмауэр не знает доменов.

## Решение
Одно правило Windows Defender Firewall (группа `Claude kill switch`):
- Outbound, Block, все программы, Profile Any.
- RemoteAddress: `160.79.104.0/21`, `2607:6bc0::/48` (сеть Anthropic: на 160.79.104.10 резолвятся api.anthropic.com, claude.ai, claude.com, platform.claude.com, console.anthropic.com, docs, code.claude.com, mcp-proxy.anthropic.com; AAAA у api.anthropic.com и claude.ai = 2607:6bc0::10. На исходной машине глобального IPv6 нет, поэтому IPv6-часть правила не проверялась). Плюс IP CDN Anthropic на Google Cloud, которые резолвятся при каждом запуске: `a-cdn.anthropic.com`, `assets.claude.ai`, `downloads.claude.ai`.
- Interfaces: ВСЕ IP-интерфейсы, КРОМЕ туннелей (`AmneziaVPN`, `happ-*`, `tun2*`; список задаётся `-VpnAlias`, маски разрешены) и loopback.
- Логика: при поднятом VPN эти адреса маршрутизируются в туннель, у соединения локальный интерфейс = туннель, правило не срабатывает. Без VPN соединение идёт через Ethernet/Wi-Fi и блокируется (WSAEACCES). Прямые соединения самого VPN-клиента к Anthropic через Ethernet (например, xray/sing-box с маршрутом "direct") тоже должны блокироваться, потому что правило для всех программ (вытекает из устройства правила, отдельно не проверялось).

Автообновление: задача Планировщика `Claude kill switch refresh` от SYSTEM.
- Триггеры: события 10000 и 10001 в `Microsoft-Windows-NetworkProfile/Operational` (подключилась или отключилась любая сеть: новый адаптер, Wi-Fi, VPN; 10001 нужно, чтобы при падении VPN его IP убрался из WSL-Allow), при старте системы, ежедневно в 12:00 (обновить IP CDN).
- Запускает копию скрипта `C:\Program Files\ClaudeKillSwitch\claude-killswitch.ps1` (писать туда могут только админы и SYSTEM; нельзя давать SYSTEM исполнять файл, который пользователь может изменить) под `powershell.exe` 5.1. Лог: `last-run.log` в той же папке.
- Правило обновляется на месте (`Set-NetFirewallRule`), без удаления и пересоздания, чтобы не было окна без защиты. Если DNS недоступен, остаются прежние IP CDN.
- `MultipleInstances Queue`, чтобы не терять события, пришедшие во время работы задачи.

### WSL (тот же скрипт, та же задача)
Правило Windows Firewall на трафик WSL НЕ действует (проверено в mirrored mode: TTL-ограниченный SYN из WSL через `eth2` = Ethernet к 160.79.104.10 и CDN доходил до роутера, как и к ya.ru). Трафик WSL фильтрует Hyper-V firewall (Win11 22H2+), поэтому для WSL отдельная пара правил Hyper-V (`VMCreatorId` WSL `{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}`):
- `ClaudeKillSwitch-WSL-Tunnel`: Outbound **Allow**, `RulePriority 10`, `LocalAddresses` = IP туннельных адаптеров (по тому же `-VpnAlias`, без fe80), `RemoteAddresses` = адреса Anthropic.
- `ClaudeKillSwitch-WSL-Block`: Outbound **Block**, `RulePriority 20`, `RemoteAddresses` = адреса Anthropic, с любых локальных адресов.
- Логика: у Hyper-V firewall нет условия по интерфейсу, но в mirrored mode пакет из WSL несёт IP того адаптера Windows, через который уходит (через `happ-xray` — 172.19.0.1, через Ethernet — LAN-адрес машины). Меньший `RulePriority` проверяется первым, поэтому Allow с IP туннеля перекрывает Block.
- Отказ в закрытую сторону: если туннеля нет (Allow удалён) или он сменил имя/IP, Anthropic из WSL блокируется до следующей синхронизации, а не идёт напрямую.
- Обновляет та же задача (события сети, старт, 12:00). Порядок: сначала Allow, потом Block, чтобы ни первая установка, ни смена IP CDN не блокировали туннельный трафик даже на миг. Правила меняются на месте (`Set-NetFirewallHyperVRule`). Каждая синхронизация заново выставляет все условия (Action, RulePriority, Enabled, Direction, Profiles, VMCreatorId, адреса), поэтому отключённое или переставленное правило возвращается. Секция WSL работает с `$ErrorActionPreference = 'Stop'`: при ошибке задача завершается неуспешно, и строки `WSL: Anthropic only from ...` в логе нет.
- В Allow не попадают link-local адреса туннеля (`fe80:*`, APIPA `169.254.*`: это не настройка туннеля).
- Из WSL правила не снять даже через `sudo`: они на стороне Windows, а менять их может только админ Windows. Действуют на все дистрибутивы.

## Почему именно так (грабли)
- Брандмауэр Windows не фильтрует по доменам, поэтому Anthropic определяется только по IP.
- В брандмауэре Windows Block важнее Allow: схему "блок всего + разрешить VPN" сделать нельзя. Поэтому блок ставится на все НЕ-туннельные интерфейсы.
- `-InterfaceType` не используется: wintun/WireGuard имеет IfType 53, и неясно, как брандмауэр его классифицирует (может попасть в Wired). Поэтому явный список алиасов и задача, которая его обновляет.
- Правило привязано к конкретным интерфейсам, существующим на момент применения, поэтому новый адаптер (USB-модем, раздача с телефона, док-станция) нужно добавлять. Это делает задача по событию 10000. Окно до срабатывания задачи — несколько секунд.
- pwsh из Microsoft Store лежит по пути с версией (WindowsApps\...), который меняется при обновлении. Запуск такого pwsh от SYSTEM не проверяли, решили не рисковать. Поэтому задача использует Windows PowerShell 5.1, и скрипт должен быть совместим с 5.1 (без `??`, тернарного оператора, `Encoding.Latin1`).
- Задачу от SYSTEM не видно из-под обычного пользователя (`Get-ScheduledTask` её не возвращает). Поэтому `-Status` без админа показывает время последнего запуска по `last-run.log`.
- ПЕРЕД установкой проверь, что каждый блокируемый адрес при поднятом VPN маршрутизируется в туннель: `Find-NetRoute -RemoteIPAddress 160.79.104.10`. Иначе Anthropic будет заблокирован всегда, даже с VPN. Например, в split-tunnel режиме адресов может не быть в списке VPN-клиента.
- Claude Code, насколько известно, не использует системный прокси Windows, только `HTTPS_PROXY` (в сессии это не проверялось). Значит, в режиме "системный прокси" (без TUN) он пойдёт мимо прокси-клиента, а через Ethernet будет заблокирован.
- WSL: брандмауэр хоста трафик VM не видит, а у Hyper-V firewall нет условия по интерфейсу (только адреса, порты, протокол, профиль). Поэтому туннель определяется по IP источника, и работает это только в **mirrored mode**. В NAT mode у WSL свой IP (172.x), он не совпадёт с IP туннеля. `-Status` предупреждает, если в `.wslconfig` не `networkingMode=mirrored` или если Hyper-V firewall для WSL выключен (`firewall=false`).
- WSL: в отличие от хоста, Block в Hyper-V firewall молча отбрасывает пакеты. Без VPN Claude Code в WSL не получает отказ сразу, а ждёт таймаута соединения.
- WSL: имена интерфейсов в Linux (`eth0`, `eth1`, `eth2`) не совпадают с алиасами Windows, и их порядок может меняться. Поэтому nftables внутри WSL отвергли: пришлось бы сопоставлять интерфейсы по IP через interop, держать свою службу, а root в WSL (и Claude с NOPASSWD sudo) мог бы правило снять.
- WSL: Allow проверяет только IP источника. Root в WSL может намеренно отправить пакет с IP туннеля через не-туннельный интерфейс (`ip route add 160.79.104.0/21 dev eth2 src 172.19.0.1`), и Allow его пропустит. Защита рассчитана на случайные утечки (VPN упал, программа ушла в обход), а не на злонамеренный root в WSL. Обычная маршрутизация Linux так не делает.
- WSL: туннели внутри Linux (tailscale exit node, WireGuard или `ssh -D` из WSL) Hyper-V firewall не видит: для него это внешний UDP/TCP к серверу туннеля. Если такой туннель уводит из WSL весь трафик (например, Tailscale с exit node), нужен ещё nft-блок Anthropic на его интерфейсе (`tailscale0`).
- WSL: проверка "через Ethernet" из Linux — только с `SO_BINDTODEVICE` (`curl --interface eth2`, `traceroute -i eth2`). Привязка к IP без устройства в Linux маршрут не меняет (weak host model): пакет уйдёт в туннель с чужим IP источника и будет заблокирован, но это ничего не доказывает.

## Как было на исходной машине (на новой может отличаться!)
- Win11 Pro, русская локаль: адаптеры `Ethernet`, `Беспроводная сеть`, `Беспроводная сеть 2..4`, `vEthernet (Default Switch)`.
- AmneziaVPN: адаптер `AmneziaVPN` (WireGuard Tunnel). Split tunnel routeMode=1 (через VPN идут только адреса из списка). Список хранится в `HKCU\Software\AmneziaVPN.ORG\AmneziaVPN\Conf`, значения `ForwardSites`/`ExceptSites` (Qt @Variant, только IP/CIDR). В списке были `160.79.104.0/21`, `34.32.0.0/11`, `34.64.0.0/10`, `35.184.0.0/13`, то есть все адреса Anthropic шли в туннель.
- Happ (`C:\Program Files\FlyFrogLLC\Happ`, служба HappService). **Имя TUN-адаптера меняется между версиями**, отсюда маска `happ-*`:
  - Happ 4.3.0: адаптер `happ-xray` (описание "Happ Tunnel"). Лог службы теперь в `C:\ProgramData\Happ\logs\happd.log`; старый `%LOCALAPPDATA%\Happ\logs\happd.log` больше не пишется. Служба ставит свои WFP-фильтры для защиты DNS (21 фильтр); с нашим правилом они не конфликтуют.
  - До 4.3: sing-box создавал адаптер `happ-tun` (описание "sing-tun Tunnel"; конфиг `%LOCALAPPDATA%\Happ\config.json`: auto_route, strict_route) и передавал трафик в xray (socks 127.0.0.1:10808).
  - Режим tun2proxy, судя по истории сетевых профилей, создаёт адаптер `tun2`. Вживую не проверялось, поэтому в списке маска `tun2*`.
  - Профиль маршрутизации RoscomVPN (`%LOCALAPPDATA%\Happ\routing.json`; в 4.3 это профиль подписки с `selectedProfile`): Anthropic нет в списках direct. Это подтверждено и на практике: через Happ HTTPS к api.anthropic.com работает, хотя прямой выход к Anthropic через Ethernet заблокирован.
- Claude Code (нативный установщик): `%USERPROFILE%\.local\bin\claude.exe`.
- WSL 3.0.1.0 (`wslinfo --version`), Ubuntu с systemd, `.wslconfig`: `networkingMode=mirrored`, `dnsTunneling=true`. Hyper-V firewall для WSL: Enabled, DefaultOutboundAction Allow. Интерфейсы Linux: `eth0` = `happ-xray` (172.19.0.1/30, default route metric 1), `eth2` = `Ethernet` (LAN-адрес), `eth1` = Wi-Fi (down), `tailscale0` (Tailscale внутри WSL, без exit node), `loopback0`. Claude Code в WSL: `~/.local/bin/claude` (Linux-версия), без `HTTPS_PROXY`.

## Установка на новой машине
1. Проверь имена туннельных адаптеров (`Get-NetAdapter`) и при необходимости поправь `-VpnAlias` (значение по умолчанию в param).
2. Подними VPN и проверь маршруты: `Find-NetRoute -RemoteIPAddress 160.79.104.10` и IP трёх CDN-хостов. Везде должен быть туннель.
3. Положи скрипт в `%USERPROFILE%\.claude\claude-killswitch.ps1` и выполни из админского PowerShell: `.\claude-killswitch.ps1 -Install`.
   Если агент работает без прав админа (если pwsh не установлен, вместо `pwsh` используй `powershell`): `Start-Process pwsh -Verb RunAs -Wait -ArgumentList '-NoProfile','-Command',"& '<script>' -Install *>&1 | Out-File '<log>'"`, затем прочитай лог. Пользователь подтверждает UAC.
4. `.\claude-killswitch.ps1 -Status`: в колонке Route туннель, в Works `yes`, нет предупреждений.
5. WSL: Windows 11 22H2+, `wslinfo --networking-mode` = `mirrored`. В `-Status` строка `WSL allowed : from <IP туннеля>`, предупреждений нет. Из WSL `ip route get 160.79.104.10` должен показывать интерфейс с IP туннеля.
   Из WSL elevated-запуск: `/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -Command "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','<launcher.ps1>'"`. Лаунчер с `-Install` и выводом в лог положи в Windows-путь (например `%TEMP%`), а не в `\\wsl$`: видит ли elevated-процесс `\\wsl$`, не проверялось. Скрипт без `-ExecutionPolicy Bypass` не запустится, политика по умолчанию его блокирует.

## Проверка, что блокировка работает (без отключения VPN)
Привязать сокет к IP физического адаптера, тогда маршрут идёт мимо туннеля. Код для pwsh 7 (оператор `??`); имя адаптера `Ethernet` поправь под машину:
```powershell
function Test-Tcp($ip, $src) {
    $c = if ($src) { [Net.Sockets.TcpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Parse($src), 0)) } else { [Net.Sockets.TcpClient]::new() }
    try { if ($c.ConnectAsync($ip, 443).Wait(4000)) { 'connected' } else { 'timeout' } }
    catch { $_.Exception.InnerException.InnerException.Message ?? $_.Exception.InnerException.Message }
    finally { $c.Dispose() }
}
$nic = (Get-NetIPAddress -InterfaceAlias Ethernet -AddressFamily IPv4).IPAddress
Test-Tcp 160.79.104.10 $nic    # ожидается отказ: WSAEACCES 10013 ("доступ к сокету запрещён" / "forbidden by its access permissions")
Test-Tcp 77.88.55.242  $nic    # контроль (ya.ru): connected, то есть остальной трафик не затронут
# Через туннель проверяй настоящим HTTPS: TUN-клиенты (sing-box, xray) обычно принимают TCP-рукопожатие локально,
# поэтому "connected" через туннель ещё не значит, что сервер достижим.
(Invoke-WebRequest https://api.anthropic.com -Method Head -SkipHttpErrorCheck).StatusCode   # 404 = Anthropic ответил
```
Результаты на исходной машине:
- AmneziaVPN: доступ к Anthropic и CDN через Ethernet отказан, ya.ru через Ethernet открывается, через туннель Anthropic доступен.
- Happ до 4.3 (`happ-tun`): то же самое, плюс HTTPS через туннель вернул 404. Автообновление: задача запустилась через 2 с после подключения адаптера.
- Happ 4.3.0 (`happ-xray`), после исправления маски: задача запустилась через 3 с после подключения адаптера, и `happ-xray` не попал в блокируемые. HTTPS к api.anthropic.com вернул 404, доступ к Anthropic через Ethernet отказан, ya.ru через Ethernet открывается. Claude Code работает через Happ.

### Проверка из WSL
Сокет привязывается к устройству (`-i eth2` = Ethernet). TTL=1, поэтому пакет умирает на роутере и до Anthropic не доходит, даже если блокировка не работает. Блок Hyper-V отбрасывает пакет молча, поэтому признак блокировки — `* * *` вместо адреса роутера:
```bash
t(){ printf '%-15s via %s: ' $1 $2; sudo timeout 15 traceroute -n -T -p 443 -i $2 -f 1 -m 1 -q 3 -w 2 $1 | tail -1; }
for ip in 160.79.104.10 $(getent ahostsv4 a-cdn.anthropic.com | awk 'NR==1{print $1}'); do t $ip eth2; done   # ожидается: 1  * * *
t 77.88.55.242 eth2                                   # контроль (ya.ru): 1  <IP роутера> ...
ip route get 160.79.104.10                            # dev <туннель> src <IP туннеля>
curl -sS -o /dev/null -w '%{http_code} from %{local_ip}\n' -I https://api.anthropic.com   # 404 from <IP туннеля>
```
Имя устройства Ethernet в WSL смотри по IP: `ip -br addr` и сравни с `Get-NetIPAddress` в Windows.

Результаты (Happ 4.3.0): ДО установки WSL-правил Anthropic и CDN через `eth2` доходили до роутера, то есть утечка. Перед установкой проверили приоритеты на ya.ru: Block@20 + Allow@10 с `LocalAddresses 172.19.0.1`. Через `eth2` — блок, через туннель — HTTPS 302, контрольный IP Яндекса не затронут. ПОСЛЕ установки: 160.79.104.10 и все 3 IP CDN через `eth2` — `* * *`, ya.ru через `eth2` — ответ роутера. Через туннель api.anthropic.com 404, a-cdn 404, claude.ai и downloads.claude.ai 403 (сервер ответил). Задача от SYSTEM отработала с результатом 0 и записала `WSL: Anthropic only from 172.19.0.1`. Claude Code в WSL работает.
После правок по ревью: Block отключили вручную, и `-Install` включил его обратно. Триггер подписан на 10000 и 10001. Все проверки выше повторены с тем же результатом.
Выключение VPN (Happ 4.3.0): `happ-xray` отключился (событие 10001), через 3 с задача удалила Allow (`WSL: Anthropic only from nowhere`). Из WSL маршрут к Anthropic пошёл через `eth2`, пробы к Anthropic и 3 IP CDN остались без ответа, ya.ru дошёл до роутера. В Windows пробы к Anthropic через Ethernet получили отказ 10013, ya.ru ушёл (таймаут). При включении (событие 10000) через 5 с задача вернула Allow с 172.19.0.1, HTTPS через туннель — 404, а через `eth2` Anthropic по-прежнему заблокирован. Выключить туннель — значит оборвать саму сессию Claude в WSL, поэтому проверка запускается вручную. Для неё есть `claude-killswitch-vpn-off-test.sh` (лежит рядом). Выключи VPN и запусти из WSL `bash claude-killswitch-vpn-off-test.sh [IP туннеля]`. Он проверяет, что Allow удалён, что пробы из WSL и Windows с TTL=1 к Anthropic блокируются (в WSL нет ответа, в Windows сразу отказ 10013), а контрольная проба к ya.ru уходит. Каждая проба — один TCP SYN с TTL=1, поэтому до Anthropic ничего не доходит, даже если блок сломан.
Вторая машина (WSL Ubuntu 26.04 + docker-desktop, mirrored, Happ 4.3.0 `happ-xray` 172.19.0.1):
- До установки WSL-правил из WSL через `eth2` к Anthropic и CDN был ответ роутера, то есть утечка.
- После установки: 4 адреса Anthropic через `eth2` — `* * *`, ya.ru доходит до роутера. HTTPS из WSL через туннель: api.anthropic.com 404, a-cdn 404, claude.ai 403. В Windows: через Ethernet отказ 10013, HTTPS через туннель 404.
- `claude-killswitch-vpn-off-test.sh`: PASSED. После события 10001 задача через 2 с удалила Allow. После включения (событие 10000) через 2 с Allow вернулся с 172.19.0.1, HTTPS из WSL — 404.

## Если Claude перестал работать через VPN
Типичная причина: VPN-клиент создал туннель с новым именем, задача сочла его обычной сетью и добавила в блокируемые. Так было при обновлении Happ до 4.3: `happ-tun` → `happ-xray`.
1. `.\claude-killswitch.ps1 -Status`: если в Route новый адаптер, а в Works `NO: blocked`, значит туннель не в `-VpnAlias`.
2. Имена подключившихся сетей: `Get-WinEvent -LogName Microsoft-Windows-NetworkProfile/Operational -MaxEvents 30 | ? Id -eq 10000`. Имя смотри в поле Name в EventData.
3. Добавь имя или маску в default `-VpnAlias` в скрипте и выполни `-Install` от админа. Задача получает список туннелей аргументом, поэтому нужна именно переустановка.
4. Если Route не туннель, а Ethernet, значит VPN-клиент не заворачивает адрес в туннель (split tunnel или direct-правило). Чинить нужно маршрутизацию VPN, а не правило.
5. Только в WSL не работает (на Windows работает): в `-Status` смотри `WSL allowed` и предупреждение `Tunnel IPs not allowed for WSL`. Туннель сменил IP, а задача ещё не отработала → выполни синхронизацию от админа. Проверь `wslinfo --networking-mode`: в NAT mode WSL всегда заблокирован. Из WSL `ip route get 160.79.104.10`: src должен быть IP туннеля.
6. Аварийный откат, если сессия Claude в WSL потеряла API: из админского PowerShell `Get-NetFirewallHyperVRule -Name 'ClaudeKillSwitch-WSL-*' | Remove-NetFirewallHyperVRule` (Windows-правило останется) или `-Remove` (снимет всё).

## Команды
```
.\claude-killswitch.ps1 -Install   # копия в Program Files + задача + синхронизация хоста и WSL (админ)
.\claude-killswitch.ps1            # однократная синхронизация (админ)
.\claude-killswitch.ps1 -Status    # покрытие, маршруты, WSL, последний автозапуск (без админа)
.\claude-killswitch.ps1 -Remove    # удалить правило хоста, правила WSL, задачу и копию (админ)
# из WSL: /mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\<user>\.claude\claude-killswitch.ps1' -Status
```
После правки скрипта в `~\.claude` снова запусти `-Install`, чтобы обновить копию в Program Files.

## Скрипт целиком: claude-killswitch.ps1
```powershell
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
```
