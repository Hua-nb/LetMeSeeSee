//! 进程现场模块：当前正在运行的进程快照（应急第一问"对方现在在不在线"）。
//! 数据源：PowerShell Get-CimInstance Win32_Process（命令行/路径/父进程/创建时间）。
//! 时间线只放"需要关注"的进程（临时/公共/ProgramData 目录、LOLBAS、无路径），
//! 完整清单进原表——避免数百个正常进程刷爆时间线。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use serde_json::Value;
use std::time::Instant;

pub const MODULE: &str = "进程现场";

const RAW_COLS: &[&str] = &["PID", "名称", "路径", "命令行", "父PID", "创建时间", "判定"];

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub ppid: u32,
    pub path: String,
    pub cmd: String,
    pub created: String,
}

/// 解析 Win32_Process 的 JSON 输出（纯函数便于测试）
pub fn parse_procs(json: &Value) -> Vec<ProcInfo> {
    json.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|o| {
                    Some(ProcInfo {
                        pid: o.get("Pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                        name: o.get("Name").and_then(|v| v.as_str()).unwrap_or("").into(),
                        ppid: o.get("PPid").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                        path: o.get("Path").and_then(|v| v.as_str()).unwrap_or("").into(),
                        cmd: o.get("Cmd").and_then(|v| v.as_str()).unwrap_or("").into(),
                        created: o.get("Created").and_then(|v| v.as_str()).unwrap_or("").into(),
                    })
                })
                .filter(|p| !p.name.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// 进程关注判定：返回命中的规则 id 列表（空=正常，不进时间线）。
/// 落点规则只看可执行映像路径——命令行参数引用 Temp/Public 是合法常态
/// （如 crashpad 的 --database=%TEMP%），看整串 hay 会大量误报
pub fn proc_flags(p: &ProcInfo) -> Vec<(&'static str, Sev)> {
    let mut out = Vec::new();
    if crate::suspicion::is_public_dir(&p.path)
        && crate::suspicion::is_executable_file(&p.path)
    {
        out.push(("R-006", Sev::Red));
    }
    if crate::suspicion::is_temp_dir(&p.path)
        && crate::suspicion::is_executable_file(&p.path)
    {
        out.push(("R-004", Sev::Yellow));
    }
    if crate::suspicion::is_programdata(&p.path)
        && crate::suspicion::is_executable_file(&p.path)
    {
        out.push(("R-017", Sev::Yellow));
    }
    if crate::suspicion::is_lolbas(&p.path) || crate::suspicion::is_lolbas(&p.name) {
        out.push(("R-005", Sev::Yellow));
    }
    // 混淆/下载参数（命令行参数本就是判定对象）
    if crate::suspicion::cmdline_suspicious(&p.cmd).is_some() {
        out.push(("R-003", Sev::Red));
    }
    // 无路径的进程：常见于保护进程/驱动级隐藏（用户态进程正常都有可执行映像）
    if p.path.is_empty() {
        out.push(("R-004", Sev::Gray));
    }
    out
}

/// 解析"PID\tPPID\t名称\t路径\t创建时间\t命令行"行（PS 5.1 的 ConvertTo-Json
/// 序列化数百对象需 10s+，行格式毫秒级；字段内制表/换行已在 PS 侧替换为空格）
pub fn parse_proc_lines(text: &str) -> Vec<ProcInfo> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() < 6 {
                return None;
            }
            Some(ProcInfo {
                pid: f[0].parse().ok()?,
                ppid: f[1].parse().ok()?,
                name: f[2].into(),
                path: f[3].into(),
                created: f[4].into(),
                cmd: f[5..].join("\t"),
            })
        })
        .filter(|p| !p.name.is_empty())
        .collect()
}

/// "yyyy-MM-dd HH:mm:ss"（本地墙上时间，PS 侧显式格式化输出）→ 毫秒时间戳。
/// 进程树排序/父推断用；解析失败返回 0（降级为无时间）。
pub fn local_str_to_ms(s: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|nd| {
            use chrono::TimeZone;
            chrono::Local.from_local_datetime(&nd).single()
        })
        .map(|dt| dt.timestamp_millis())
        .unwrap_or(0)
}

fn query_procs(logs: &mut Vec<String>) -> Vec<ProcInfo> {
    // Win32 API 直调（CreateToolhelp32Snapshot + NtQueryInformationProcess）：
    // 零子进程、零 PowerShell 依赖，数据源与 Get-CimInstance Win32_Process 完全一致。
    // 非提权：路径/时间可读用户进程，命令行仅自身——提权后全覆盖。
    match crate::winapi::enumerate_processes() {
        Ok(procs) => {
            logs.push(format!(
                "Win32 API 枚举 {} 个进程（路径 {} 个、命令行 {} 个——命令行需管理员权限）",
                procs.len(),
                procs.iter().filter(|p| !p.path.is_empty()).count(),
                procs.iter().filter(|p| !p.cmd.is_empty()).count(),
            ));
            procs
        }
        Err(e) => {
            logs.push(format!("进程枚举失败：{e}"));
            Vec::new()
        }
    }
}

pub struct LiveProcCollector;

impl Default for LiveProcCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for LiveProcCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "现场快照（进程/网络）"
    }

    /// 展示职责已由「进程树」页承接（2026-09-28 用户决策）：侧边栏不显示本模块；
    /// 快照仍采集（进程树的数据源），关注进程事件仍进时间线喂规则计数
    fn hidden(&self) -> bool {
        true
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let procs = query_procs(&mut logs);
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut flagged = 0usize;

        for p in &procs {
            let flags = proc_flags(p);
            // 无路径的受保护系统进程（smss/csrss/Registry 等）是常态，只进原表不进
            // 时间线；时间线只放有实质落点/命令行特征的进程
            let only_nopath = flags
                .iter()
                .all(|(rid, _)| *rid == "R-004") && p.path.is_empty();
            if !flags.is_empty() {
                flagged += 1;
            }
            // 进程树种子：现场快照（进程树唯一数据源，2026-09-28 定稿）
            let max_sev = flags.iter().map(|(_, s)| *s).max().unwrap_or(Sev::None);
            crate::proctree::push(
                MODULE,
                crate::proctree::ProcSeed {
                    pid: p.pid,
                    ppid: p.ppid,
                    image: if p.path.is_empty() {
                        p.name.clone()
                    } else {
                        p.path.clone()
                    },
                    cmd: p.cmd.clone(),
                    start_display: if p.created.is_empty() {
                        "（未知）".into()
                    } else {
                        format!("{}.000", p.created)
                    },
                    start_ms: local_str_to_ms(&p.created),
                    sev: max_sev,
                    tags: flags.iter().map(|(rid, _)| rid.to_string()).collect(),
                },
            );
            let note = if flags.is_empty() {
                String::new()
            } else {
                flags
                    .iter()
                    .map(|(rid, _)| *rid)
                    .collect::<Vec<_>>()
                    .join("、")
            };
            let time = if p.created.is_empty() {
                "（无时间戳）".to_string()
            } else {
                format!("{}.000", p.created)
            };
            if !flags.is_empty() && !only_nopath {
                let mut tags = Vec::new();
                let mut max_sev = Sev::None;
                for (rid, sev) in &flags {
                    tags.push(Tag {
                        sev: *sev,
                        text: format!("{rid} {}", rid),
                    });
                    if *sev > max_sev {
                        max_sev = *sev;
                    }
                }
                events.push(ActivityEvent {
                    time: time.clone(),
                    kind: "进程现场".into(),
                    desc: if p.path.is_empty() {
                        format!("（无路径）{}", p.name)
                    } else {
                        p.path.clone()
                    },
                    info: format!(
                        "PID {} · 父 PID {} · 命令行 {} · 运行中（现场）",
                        p.pid, p.ppid, p.cmd
                    ),
                    module: MODULE.into(),
                    sev: max_sev,
                    tags,
                });
            }
            rows.push(vec![
                p.pid.to_string(),
                p.name.clone(),
                p.path.clone(),
                p.cmd.clone(),
                p.ppid.to_string(),
                time,
                note,
            ]);
        }
        logs.push(format!(
            "共 {} 个运行中进程，需关注 {} 个（时间线仅列关注项，完整清单见原表）",
            procs.len(),
            flagged
        ));
        ModuleResult {
            module: self.id().into(),
            status: if procs.is_empty() {
                ModuleStatus::Err
            } else if flagged > 0 {
                ModuleStatus::Warn
            } else {
                ModuleStatus::Ok
            },
            count: events.len(),
            duration_ms: t0.elapsed().as_millis(),
            logs,
            events,
            raw: Some(RawTable {
                columns: RAW_COLS.iter().map(|s| s.to_string()).collect(),
                rows,
                refs: Vec::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_proc_json() {
        let v = json!([
            {"Pid":100,"Name":"x.exe","PPid":4,"Path":"C:\\Users\\Public\\x.exe","Cmd":"x.exe -k","Created":"2026-09-25 08:00:00"},
            {"Pid":101,"Name":"y.sys","PPid":100,"Path":"","Cmd":"","Created":""}
        ]);
        let p = parse_procs(&v);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].pid, 100);
        assert_eq!(p[1].path, "");
    }

    #[test]
    fn local_str_ms_converted() {
        // PS 侧输出 "yyyy-MM-dd HH:mm:ss"（本地墙上时间）
        let ms = local_str_to_ms("2026-09-28 09:59:30");
        use chrono::TimeZone;
        let expect = chrono::Local
            .with_ymd_and_hms(2026, 9, 28, 9, 59, 30)
            .single()
            .unwrap()
            .timestamp_millis();
        assert_eq!(ms, expect);
        assert_eq!(local_str_to_ms(""), 0);
        assert_eq!(local_str_to_ms("not a date"), 0);
    }

    #[test]
    fn parses_proc_line_format() {
        let text = "100\t4\tx.exe\tC:\\Users\\Public\\x.exe\t2026-09-25 08:00:00\tx.exe -k\n\
101\t100\tghost.exe\t\t\t\n\
bad line without tabs";
        let p = parse_proc_lines(text);
        assert_eq!(p.len(), 2, "{p:?}");
        assert_eq!(p[0].pid, 100);
        assert_eq!(p[0].path, r"C:\Users\Public\x.exe");
        assert_eq!(p[0].cmd, "x.exe -k");
        assert_eq!(p[1].path, "");
        // 命令行内残留制表符以第 6 字段起整体保留
        let t2 = "1\t2\ta.exe\tC:\\a.exe\t2026-01-01 00:00:00\tcmd\tpart2";
        assert_eq!(parse_proc_lines(t2)[0].cmd, "cmd\tpart2");
    }

    #[test]
    fn flags_public_temp_lolbas_procs() {
        let mk = |path: &str, name: &str| ProcInfo {
            pid: 1,
            name: name.into(),
            ppid: 4,
            path: path.into(),
            cmd: String::new(),
            created: String::new(),
        };
        let f = proc_flags(&mk(r"C:\Users\Public\svc.exe", "svc.exe"));
        assert!(f.iter().any(|(r, _)| *r == "R-006"));
        let f = proc_flags(&mk(r"C:\Users\a\AppData\Local\Temp\m.exe", "m.exe"));
        assert!(f.iter().any(|(r, _)| *r == "R-004"));
        let f = proc_flags(&mk(r"C:\Windows\System32\certutil.exe", "certutil.exe"));
        assert!(f.iter().any(|(r, _)| *r == "R-005"));
        // 正常程序不标记
        assert!(proc_flags(&mk(r"C:\Program Files\App\app.exe", "app.exe")).is_empty());
        // 无路径进程灰标记
        let f = proc_flags(&mk("", "ghost"));
        assert!(f.iter().any(|(r, _)| *r == "R-004"));
    }

    #[test]
    fn cmdline_temp_reference_not_flagged() {
        // 误报治理回归：crashpad 类进程 --database 指向 Temp 是合法常态，
        // 落点判定只看映像路径
        let p = ProcInfo {
            pid: 1,
            name: "crashpad_handler.exe".into(),
            ppid: 4,
            path: r"F:\WXWork\bugly\x64\crashpad_handler.exe".into(),
            cmd: r#"crashpad_handler.exe --database=C:\Users\user1\AppData\Local\Temp --url=x"#.into(),
            created: String::new(),
        };
        let f = proc_flags(&p);
        assert!(f.is_empty(), "{f:?}");
        // 公共桌面快捷方式路径同样不触发
        let p2 = ProcInfo {
            pid: 2,
            name: "x.lnk".into(),
            ppid: 4,
            path: r"C:\Users\Public\Desktop\x.lnk".into(),
            cmd: String::new(),
            created: String::new(),
        };
        assert!(proc_flags(&p2).is_empty());
    }

    #[test]
    fn flags_encoded_cmdline() {
        let p = ProcInfo {
            pid: 1,
            name: "powershell.exe".into(),
            ppid: 4,
            path: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
            cmd: "powershell -enc SQBFAFgA".into(),
            created: String::new(),
        };
        let f = proc_flags(&p);
        assert!(f.iter().any(|(r, s)| *r == "R-003" && *s == Sev::Red));
    }

    #[test]
    fn collector_degrades_without_ps() {
        let r = LiveProcCollector::default().run();
        assert!(!r.logs.is_empty());
    }
}
