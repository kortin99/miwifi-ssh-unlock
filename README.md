# miwifi-ssh-unlock

One-command SSH unlock for Xiaomi / Redmi (MiWiFi) routers on current stable firmware.

**No downgrade · No UART · No disassembly · No firmware flashing · No `pip install`**

[简体中文文档 →](README.zh-CN.md)

> ⚠️ **Use only on a router you own or are explicitly authorised to modify.**
> Enabling SSH voids the warranty. Unauthorised access to network equipment is
> illegal in most jurisdictions (mainland China: Criminal Law art. 285).
> The script intentionally requires the WEB admin password (or an admin `stok`)
> as an ownership gate and asks for confirmation before doing anything.

## What it does

One command takes a stock router to a working root SSH session:

1. Detect model, firmware version and serial number.
2. Log into the WEB UI to obtain a `stok` (or reuse one you supply).
3. Start a temporary HTTP server on your computer.
4. Trigger the `set_global_enable` injection; the router fetches a small shell
   stage over the LAN and runs it as root.
5. Enable the factory flags, set the root password and start dropbear.
6. Install **soft persistence** so SSH comes back after every reboot.
7. Verify port 22 and print the login command.

Pure Python 3.8+ standard library, works on macOS / Linux / Windows. Nothing is
written to the router beyond the intended config files.

## Tested and known affected firmware

Static census of 60 official ROMs ([source](https://github.com/leafnsand/xiaomi-rp01-root)):

| Model | Firmware | | Model | Firmware |
|---|---|---|---|---|
| RP01 | 1.0.67 | | RN01 | 1.0.74 |
| RP02 | 1.0.46 | | RN02 | **1.0.64 (BE6500)** |
| RP03 | 1.0.63 | | RN04 | 1.0.94 |
| RP04 | 1.0.89 | | RD01 | 1.0.52 |
| RP09 | 1.0.44 | | RD02 | 1.0.39 |
| RD03V2 | 2.0.12 | | RD08 | 1.1.96 |

End-to-end tested on **RN02 / BE6500 / MiWiFi stable 1.0.64**. Other models are
unverified; `--info` shows model and version without changing anything.

The older "four curl commands" tutorials target `/api/xqsystem/start_binding`
and are patched on these versions: they return `1523`, or `code:0` without
executing anything. This tool does not use them.

## Requirements

- Python **3.8+** (standard library only)
- Computer and router on the **same LAN** (default gateway `192.168.31.1`)
- The router's **WEB admin password**, or a currently valid `stok`
- Inbound connections to your computer allowed (the router must fetch the stage)

## Quick start

```bash
git clone https://github.com/kortin99/miwifi-ssh-unlock.git
cd miwifi-ssh-unlock
python3 miwifi_ssh_unlock.py --password '你的路由器后台密码'
```

On Windows use `python` instead of `python3`. You will be asked to confirm you
own the device; in non-interactive shells add `--yes`.

Expected tail of output:

```
[6/6] 验证结果
      端口 22 : SSH-2.0-dropbear
==========================================================
 SSH 已开启
   ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1
   用户名 root   密码 <8-char password>
 已安装软固化：/data/auto_ssh/auto_ssh.sh + firewall include
==========================================================
```

Then connect and change the password immediately:

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1
passwd root          # inside the router shell
```

> `HostKeyAlgorithms=+ssh-rsa` is needed because these builds ship an older
> dropbear with an `ssh-rsa` host key; OpenSSH 8.8+ disables SHA-1 by default.

## Root password

Unless `--ssh-password` is given, the script computes the factory root password
from the serial number and writes the same value with `passwd root`:

```
md5(SN + "6d2df50a-250f-4a30-a5e6-d44fb0960aa0")[:8]
```

`SN` includes the `/`. This also works on builds with a different default.

## SSH persistence — read this

On MiWiFi, `/etc` is a **ramfs**. Everything the unlock changes there disappears
on reboot: the `channel="debug"` edit, the dropbear rc.d link, the host key and
`/etc/shadow`. Meanwhile the read-only squashfs firmware still contains
`CHANNEL='release'`, and the stock dropbear init script returns early when the
channel is `release`. So **without persistence SSH dies at the first reboot**,
even though `fac_info.ssh` stays `true` (that flag lives in nvram and is only a
flag, not a running service).

| Layer | Reboot | Contents |
|---|---|---|
| nvram (flash) | survives | `ssh_en=1`, `telnet_en=1`, `uart_en=1` |
| `/data` (ubifs, flash) | survives | user config, `/data/etc/config`, `/data/etc/shadow` |
| `/etc` (ramfs) | **wiped** | dropbear init edit, rc.d link, host key, shadow |
| `/` (squashfs, read-only) | unchanged | stock dropbear, `CHANNEL='release'` |

`uci commit` is mirrored in real time into `/data/etc/config`, so a firewall
`include` is enough to restore SSH on every boot. The script installs:

- `/data/auto_ssh/auto_ssh.sh` — idempotent. If dropbear is already running it
  exits immediately; otherwise it restores the host key, sets `channel="debug"`,
  re-adds `ssh_en=1`, enables and restarts dropbear.
- `/data/auto_ssh/keys/` — backup of the RSA host key, so a reboot does not
  trigger `REMOTE HOST IDENTIFICATION HAS CHANGED`.
- `firewall.auto_ssh` include, executed by `S19firewall` (`fw3 start`) at boot.

Verify after a reboot, no credentials needed:

```bash
python3 miwifi_ssh_unlock.py --verify
```

For a 7-item deep check (script / syntax / include / on-flash config / host key /
nvram / port 22):

```bash
python3 miwifi_ssh_unlock.py --password '后台密码' --verify
```

Soft persistence survives ordinary reboots. It does **not** survive an official
firmware upgrade, a factory reset or a mesh reset — re-run the unlock (or
`--persist-only`) afterwards. Hard persistence (writing `bdata` / `crash`
partitions) is deliberately not implemented: higher brick risk, no benefit here.

## Commands

| Task | Command |
|---|---|
| Unlock + install persistence (default) | `python3 miwifi_ssh_unlock.py --password 'PWD'` |
| Read-only device info | `python3 miwifi_ssh_unlock.py --info` |
| Quick post-reboot check, no credentials | `python3 miwifi_ssh_unlock.py --verify` |
| Deep 7-item persistence check | `python3 miwifi_ssh_unlock.py --password 'PWD' --verify` |
| Re-install persistence only | `python3 miwifi_ssh_unlock.py --password 'PWD' --persist-only --yes` |
| Remove persistence | `python3 miwifi_ssh_unlock.py --password 'PWD' --rollback --yes` |
| Reuse an existing admin token | `... --stok <stok> --yes` |
| Preview payload/stage without injecting | `... --dry-run` |
| Re-run even though SSH is already open | `... --force` |
| Skip persistence on a fresh unlock | `... --no-persist` |

<details>
<summary>All options</summary>

| Option | Meaning |
|---|---|
| `--ip` | Router address, default `192.168.31.1` |
| `--scheme` | `http` (default) or `https` |
| `--password` | WEB admin password; `MIWIFI_PASSWORD` env var also works |
| `--stok` | Reuse a logged-in session token instead of logging in |
| `--ssh-password` | Custom root password instead of the SN-derived one |
| `--lhost` | LAN IP of this computer reachable by the router (auto-detected) |
| `--lport` | Local stage HTTP port, default `8000` (auto-picks a free one) |
| `--wait` | Seconds to wait for the callback, default `15` |
| `--timeout` | HTTP timeout |
| `--verify` | Quick check (no credentials) or deep check (with credentials) |
| `--persist-only` | Re-install soft persistence only |
| `--rollback` | Remove soft persistence |
| `--no-persist` | Do not install persistence on a fresh unlock |
| `--force` | Run even if SSH is already open |
| `--yes` | Skip the ownership prompt (required in non-interactive shells) |
| `--info` | Read-only device information |
| `--dry-run` | Print payload/stage, do not inject |
| `--cmd` | Advanced: run your own shell script as the stage; its log is returned |

</details>

`--verify`, `--persist-only` and `--rollback` are mutually exclusive. Every mode
except the credential-free quick check needs a valid `stok` or the WEB password.

## Troubleshooting

| Symptom | Fix |
|---|---|
| No callback / `注入没有生效` | Allow inbound connections to Python (Windows Defender Firewall is the usual culprit), then `--lhost <your LAN IP>`. Self-test `http://<lhost>:<port>/S` from another LAN device |
| `stok` rejected | Tokens expire. Re-login to the WEB UI, or use `--password` and let the script log in. Note `fac_info` works without a token, so it is **not** a valid token check |
| `{"code":0}` but nothing happened | Expected. The API response is not proof of execution; only the callback and port 22 count |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | `ssh-keygen -R 192.168.31.1`. With persistence installed the host key is restored from `/data`, so this should not occur |
| `no matching host key method` | Add `-o HostKeyAlgorithms=+ssh-rsa` |
| LAN request goes through a proxy / 502 | The script bypasses system proxies for LAN requests automatically |
| SSH gone after a firmware upgrade | Re-run with `--force`, or `--persist-only` if SSH is still open |

## How it works (technical)

Newer firmware patched the classic `start_binding` injection. This tool uses the
second injection point published in 2026:

```
POST /cgi-bin/luci/;stok=<stok>/api/device_security/local_access/set_global_enable
```

The controller reads the whole parameter table at once (bypassing `hackCheck` /
mac validation), upper-cases `mac`, then interpolates it unescaped into a
root-level `os.execute("milog.sh -m '...'")`. Payload constraints:

- `;` and `&` are consumed by URL decoding → use `|` and newlines
- the payload is upper-cased → it must contain no functional lowercase letters
- `curl` is reached via a glob; the stage is fetched over plain HTTP and sourced
  from a pipe, so no stage file is ever written to the router

The stage itself is an ordinary shell script with no such restrictions.
`--dry-run` prints both the payload and the stage.

## Security notes

- `stok` is equivalent to an admin session. Never paste it into an issue;
  re-login to the WEB UI to invalidate it after use.
- Change the root password right after the first login.
- Opening SSH voids the warranty. Deep persistence / flashing `bdata` can brick
  the device; back up your flash before any low-level change.
- This repository contains no serial numbers, tokens or passwords. Please keep
  it that way when contributing.

## Credits

- [leafnsand/xiaomi-rp01-root](https://github.com/leafnsand/xiaomi-rp01-root) — the `set_global_enable` research and firmware census
- [openwrt-xiaomi/xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher) — login flow reference

## License

MIT — see [LICENSE](LICENSE).
