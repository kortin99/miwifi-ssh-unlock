# miwifi-ssh-unlock

[English →](README.md)

一键开启小米 / 红米（MiWiFi）路由器 SSH，面向当前稳定版固件。

**不降级 · 不拆机 · 不接 TTL · 不刷固件 · 不需要 `pip install`**

> ⚠️ **仅限自己拥有或获得明确授权的设备。** 开启 SSH 会失去官方保修；未授权访问网络设备在多数司法辖区违法（《中华人民共和国刑法》第 285 条）。脚本刻意要求提供 WEB 后台密码（或管理员 `stok`）作为归属门槛，并在执行前要求确认。

## 它能做什么

一条命令完成：

1. 读取型号、固件版本、SN
2. 用后台密码登录取 `stok`（也可直接给 `stok`）
3. 在本机起一个临时 HTTP 服务
4. 触发 `set_global_enable` 注入，路由器从局域网取回一段 shell stage 并以 root 执行
5. 打开出厂开关、写入 root 密码、启动 dropbear
6. **安装软固化**，让重启后 SSH 自动恢复
7. 校验 22 端口，打印登录命令

全程只用 Python 3.8+ 标准库，macOS / Linux / Windows 均可。除预期配置文件外不往路由器 flash 写东西。

## 适用版本

对 60 份官方固件做静态普查后命中的分支（[来源](https://github.com/leafnsand/xiaomi-rp01-root)）：

| 型号 | 固件 | | 型号 | 固件 |
|---|---|---|---|---|
| RP01 | 1.0.67 | | RN01 | 1.0.74 |
| RP02 | 1.0.46 | | RN02 | **1.0.64（BE6500）** |
| RP03 | 1.0.63 | | RN04 | 1.0.94 |
| RP04 | 1.0.89 | | RD01 | 1.0.52 |
| RP09 | 1.0.44 | | RD02 | 1.0.39 |
| RD03V2 | 2.0.12 | | RD08 | 1.1.96 |

**完整实测机型：RN02 / BE6500 / MiWiFi 稳定版 1.0.64。** 其余型号未做端到端验证，`--info` 可以只读查看型号与版本。

### 为什么网上的"四条 curl"不管用

在 1.0.64 上逐个实测过经典注入口：

| 接口 | 结果 |
|---|---|
| `start_binding`（新旧两种 payload） | `code:1523`，注入已修 |
| `arn_switch`、`set_mac_filter`、`set_macfilter_rules` | 返回 `code:0`，但 `sleep 3` 计时与 UCI 标记回读证明命令根本没执行 |
| `xqdatacenter/request` | `ParameterError` |
| `set_config_iotdev` | `code:1523` |

所以"1.0.64 必须断电砍分区降级到 1.0.43"的说法已经过时。本项目用的是 2026 年公开的第二个注入点，免降级、免拆机。

## 准备条件

- Python **3.8+**（仅标准库）
- 电脑与路由器在**同一局域网**（默认网关 `192.168.31.1`）
- 路由器 **WEB 后台密码**（或一个仍然有效的 `stok`）
- 本机允许入站连接（路由器要能来取 stage，Windows 防火墙最常见）

## 快速开始

```bash
git clone https://github.com/kortin99/miwifi-ssh-unlock.git
cd miwifi-ssh-unlock
python3 miwifi_ssh_unlock.py --password '你的路由器后台密码'
```

Windows 把 `python3` 换成 `python`。交互环境会要求确认设备归属；CI / 非交互环境加 `--yes`。

成功后输出末尾大致是：

```
[6/6] 验证结果
      端口 22 : SSH-2.0-dropbear
==========================================================
 SSH 已开启
   ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1
   用户名 root   密码 <8 位密码>
 已安装软固化：/data/auto_ssh/auto_ssh.sh + firewall include
==========================================================
```

登录并立刻改密码：

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1
passwd root          # 在路由器 shell 内执行
```

> 必须带 `HostKeyAlgorithms=+ssh-rsa`：这些固件自带的 dropbear 用的是老式 `ssh-rsa` host key，OpenSSH 8.8+ 默认禁用了 SHA-1 签名。

## root 密码怎么来的

不给 `--ssh-password` 时，脚本按小米算法从 SN 算出出厂 root 密码，并用 `passwd root` 写入相同的值：

```
md5(SN + "6d2df50a-250f-4a30-a5e6-d44fb0960aa0")[:8]
```

SN 包含 `/`。这样即使某些版本默认密码不同，也能保证算出来的这个可用。

## SSH 固化（重点）

**不固化，重启一次 SSH 就没了。** 原因在分区：

| 层 | 重启后 | 内容 |
|---|---|---|
| nvram（flash） | 保留 | `ssh_en=1`、`telnet_en=1`、`uart_en=1` |
| `/data`（ubifs，flash） | 保留 | 用户配置、`/data/etc/config`、`/data/etc/shadow` |
| `/etc`（**ramfs 内存盘**） | **全部清空** | `channel="debug"` 改动、rc.d 自启链接、host key、`/etc/shadow` |
| `/`（squashfs 只读） | 原样 | 原版 dropbear、`CHANNEL='release'` |

原版 dropbear 启动脚本里有：

```sh
if [ "$flg_ssh" != "1" -o "$channel" = "release" ]; then return 0; fi
```

重启后 `channel` 变回 `release`，服务直接 return。注意 `fac_info` 里 `ssh=true` 会保留，但**那只是 nvram 里的标志位，不代表服务在跑**，很容易被误导。

好消息：`uci commit` 会实时镜像到 `/data/etc/config`（实测写入/删除两边 md5 同步），所以一条 firewall `include` 就够。脚本会装：

- `/data/auto_ssh/auto_ssh.sh`：幂等。dropbear 已经在跑就立即退出，不踢掉现有 SSH；否则恢复 host key、改回 `channel="debug"`、补 `ssh_en=1`、`enable + restart`。
- `/data/auto_ssh/keys/`：备份 RSA host key，避免重启后客户端报 `REMOTE HOST IDENTIFICATION HAS CHANGED`。
- `firewall.auto_ssh` include：开机由 `S19firewall` → `fw3 start` 执行。

### 重启后怎么验证

```bash
python3 miwifi_ssh_unlock.py --verify                       # 零凭据，只看 22 端口是否在线
python3 miwifi_ssh_unlock.py --password '后台密码' --verify  # 7 项深度体检
ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1        # 或者最直接：连一下
```

深度体检逐项打印 `[OK]/[FAIL]`：自启脚本存在且可执行、脚本语法、include 已配置、配置已落盘 `/data`、host key 备份一致、`nvram ssh_en`、22 端口监听。

> 脚本**不会替你重启路由器**——那会让全家断网，属于该由你决定时机的动作。脚本负责重启前后的检查和修复。

### 什么情况下会失效

- ✅ 普通断电 / 重启：软固化会自动恢复
- ❌ 官方固件升级、恢复出厂、mesh 重置：会清掉 `/data` 配置和 nvram，需重跑解锁（加 `--force`）或 `--persist-only`
- ❌ 官方修掉注入点后：需另找方案

**不建议**去动 `bdata` / `crash` 分区做"深度固化"：nvram 本来就是持久的，软固化已经够用，改分区有变砖风险，本项目刻意不实现。

## 常用命令

| 场景 | 命令 |
|---|---|
| 一键解锁（默认同时装固化） | `python3 miwifi_ssh_unlock.py --password 'PWD'` |
| 只读查看设备信息 | `python3 miwifi_ssh_unlock.py --info` |
| 重启后快速体检（零凭据） | `python3 miwifi_ssh_unlock.py --verify` |
| 重启后 7 项深度体检 | `python3 miwifi_ssh_unlock.py --password 'PWD' --verify` |
| 只重装固化，不重复解锁 | `python3 miwifi_ssh_unlock.py --password 'PWD' --persist-only --yes` |
| 卸载固化 | `python3 miwifi_ssh_unlock.py --password 'PWD' --rollback --yes` |
| 复用已登录的 token | `... --stok <stok> --yes` |
| 只打印 payload/stage 不注入 | `... --dry-run` |
| SSH 已开也要重跑 | `... --force` |
| 解锁时不装固化 | `... --no-persist` |

<details>
<summary>全部参数</summary>

| 参数 | 说明 |
|---|---|
| `--ip` | 路由器地址，默认 `192.168.31.1` |
| `--scheme` | `http`（默认）或 `https` |
| `--password` | WEB 后台密码；也可用环境变量 `MIWIFI_PASSWORD` |
| `--stok` | 复用已登录会话，跳过登录 |
| `--ssh-password` | 自定义 SSH root 密码，默认按 SN 计算 |
| `--lhost` | 本机可被路由器访问的 LAN IP，默认自动探测 |
| `--lport` | 本地 stage HTTP 端口，默认 8000（被占用自动换空闲端口） |
| `--wait` | 等待回连秒数，默认 15 |
| `--timeout` | HTTP 超时 |
| `--verify` | 快速体检（无凭据）或深度体检（有凭据） |
| `--persist-only` | 只重装软固化 |
| `--rollback` | 卸载软固化 |
| `--no-persist` | 解锁时不装固化 |
| `--force` | SSH 已开启也重新执行 |
| `--yes` | 跳过归属确认（非交互环境必需） |
| `--info` | 只读设备信息 |
| `--dry-run` | 只打印 payload/stage，不注入 |
| `--cmd` | 高级：把自己的 shell 脚本作为 stage 执行，日志会自动回传 |

</details>

`--verify` / `--persist-only` / `--rollback` 三者互斥。除零凭据快速体检外，其余模式都需要有效 `stok` 或后台密码。

## 排错

| 现象 | 处理 |
|---|---|
| 没回连 / `注入没有生效` | 放行本机防火墙对 Python 的入站连接（Windows 最常见），再用 `--lhost <本机 LAN IP>`；可从局域网另一台设备打开 `http://<lhost>:<port>/S` 自检 |
| stok 被拒 | token 会过期，重新登录后台取新的，或直接用 `--password` 让脚本自己登录。注意 `fac_info` 免鉴权，**不能**用它判断 token 是否有效 |
| 返回 `{"code":0}` 但没反应 | 正常现象，API 返回值不代表命令已执行，只认回连和 22 端口 |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | `ssh-keygen -R 192.168.31.1`；装了固化后 host key 会从 `/data` 恢复，正常不该出现 |
| `no matching host key method` | 加 `-o HostKeyAlgorithms=+ssh-rsa` |
| 局域网请求走代理报 502 | 脚本已自动绕过系统代理 |
| 升级固件后 SSH 没了 | `--force` 重跑，或 SSH 还在就用 `--persist-only` |

## 原理简述

新版固件修掉了经典的 `start_binding` 注入。本项目使用 2026 年公开的第二个注入点：

```
POST /cgi-bin/luci/;stok=<stok>/api/device_security/local_access/set_global_enable
```

控制器一次性读取整张参数表（绕过了 `hackCheck` / mac 校验），把 `mac` 转成大写后未转义拼进 root 权限的 `os.execute("milog.sh -m '...'")`。payload 有三个约束：

- `;` 和 `&` 会被 URL 解码吃掉 → 用 `|` 和换行代替
- payload 会被整体转大写 → 不能含功能性小写字母
- `curl` 通过通配符命中；stage 走明文 HTTP 取回并直接从管道 source，路由器磁盘上不留 stage 文件

stage 本身是普通 shell 脚本，不受这些限制。`--dry-run` 会把 payload 和 stage 都打印出来。

## 安全与合规

- `stok` 等价于管理员会话，别贴到 issue 里；用完退出并重新登录后台让它失效
- 首次登录后立刻 `passwd root` 改掉出厂密码
- 开启 SSH 会失去官方保修；刷 `bdata` 等底层分区有变砖风险，动手前先备份 flash
- 本仓库不含任何 SN、token、密码，贡献代码时请保持这一点

## 推送到 GitHub 前检查

- [ ] 只提交 `miwifi_ssh_unlock.py`、README、LICENSE、`.gitignore`
- [ ] 不要提交任何临时探测脚本（尤其是内嵌 `stok` 的那种）
- [ ] 提交前跑一次 `grep -R 'stok=\|stok\|SN' .` 确认没有真实凭据
- [ ] 把 README、LICENSE 里的用户名 / 版权署名换成自己的

## 致谢

- [leafnsand/xiaomi-rp01-root](https://github.com/leafnsand/xiaomi-rp01-root)：`set_global_enable` 研究与固件普查
- [openwrt-xiaomi/xmir-patcher](https://github.com/openwrt-xiaomi/xmir-patcher)：登录流程参考

## 许可证

MIT，见 [LICENSE](LICENSE)。
