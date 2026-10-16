use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{read_value, subkeys, user_sids, value_names, HKEY};
use crate::timeutil::filetime_to_local;
use std::time::Instant;

pub const MODULE: &str = "程序运行记录（UserAssist）";

pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

pub struct ParsedEntry {
    pub run_count: u32,
    pub last_exec_ft: Option<u64>,
}

/// UserAssist 条目名归一化（原始 ROT13 解码后）：
/// - 含盘符的路径 → 原样
/// - {已知文件夹GUID}\x.exe → 还原为真实路径（Win+R/开始菜单启动系统程序的形态，
///   如 {1AC14E77-…}\cmd.exe = C:\Windows\System32\cmd.exe）
/// - 未知 {GUID}\… → 原样保留（真实数据，不虚构）
/// - UWP AUMID（包名!App）→ 原样
/// - 其余（无盘符/无GUID/无AUMID的非程序条目）→ 丢弃
pub fn normalize_ua_name(decoded: &str) -> Option<String> {
    if decoded.contains(':') {
        return Some(decoded.to_string());
    }
    if decoded.starts_with('{') {
        if let Some((guid, rest)) = decoded.split_once('}') {
            let full = format!("{guid}}}"); // guid 已含开括号，补闭合括号
            let rest = rest.trim_start_matches('\\');
            const FOLDER_GUIDS: &[(&str, &str)] = &[
                // FOLDERID_System / FOLDERID_Windows（UserAssist 最常见的两个）
                ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", r"C:\Windows\System32"),
                ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", r"C:\Windows"),
            ];
            if let Some((_, path)) = FOLDER_GUIDS.iter().find(|(g, _)| g.eq_ignore_ascii_case(&full)) {
                return Some(format!(r"{path}\{rest}"));
            }
            return Some(decoded.to_string());
        }
    }
    if decoded.contains('!') && decoded.contains('.') {
        return Some(decoded.to_string()); // UWP AUMID：Microsoft.WindowsCalculator_…!App
    }
    None
}

/// Win7+ UserAssist 值结构（72 字节）：run_count@4，last_exec FILETIME@60
pub fn parse_entry(b: &[u8]) -> Option<ParsedEntry> {
    if b.len() < 68 {
        return None;
    }
    let run_count = u32::from_le_bytes(b[4..8].try_into().unwrap());
    let ft = u64::from_le_bytes(b[60..68].try_into().unwrap());
    Some(ParsedEntry {
        run_count,
        last_exec_ft: (ft > 0).then_some(ft),
    })
}

pub struct UserAssistCollector;

impl Default for UserAssistCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for UserAssistCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "程序运行记录"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let sids = user_sids();
        for sid in &sids {
            let ua_root = format!(
                r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
            );
            let cats = match subkeys(HKEY::users(), &ua_root) {
                Ok(c) => c,
                Err(e) => {
                    logs.push(format!("跳过 {sid}：{e}"));
                    continue;
                }
            };
            for cat in cats {
                let count_key = format!(r"{ua_root}\{cat}\Count");
                let names = match value_names(HKEY::users(), &count_key) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                for name in names {
                    let Ok((bytes, _ty)) = read_value(HKEY::users(), &count_key, &name) else {
                        continue;
                    };
                    let Some(decoded) = normalize_ua_name(&rot13(&name)) else {
                        continue;
                    };
                    if let Some(p) = parse_entry(&bytes) {
                        if let Some(t) = p.last_exec_ft.and_then(filetime_to_local) {
                            let ver = crate::verinfo::file_version_info(&decoded)
                                .map(|v| format!("{v} · "))
                                .unwrap_or_default();
                            events.push(ActivityEvent {
                                time: t,
                                kind: "程序运行".into(),
                                desc: decoded,
                                info: format!(
                                    "{ver}GUI 执行 {} 次 · 用户 {sid}",
                                    p.run_count
                                ),
                                module: MODULE.into(),
                                sev: Sev::None,
                                tags: vec![],
                            });
                        }
                    }
                }
            }
        }
        logs.push(format!(
            "共 {} 个用户、{} 条 GUI 执行记录",
            sids.len(),
            events.len()
        ));
        ModuleResult {
            module: self.id().into(),
            status: if events.is_empty() {
                ModuleStatus::Warn
            } else {
                ModuleStatus::Ok
            },
            count: events.len(),
            duration_ms: t0.elapsed().as_millis(),
            logs,
            events,
            raw: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_roundtrip_and_sample() {
        assert_eq!(rot13("URI"), "HEV");
        assert_eq!(rot13(&rot13("C:\\Tools\\x.exe")), "C:\\Tools\\x.exe");
    }

    #[test]
    fn parses_win7_72_byte_entry() {
        let mut b = [0u8; 72];
        b[4..8].copy_from_slice(&5u32.to_le_bytes());
        let ft: u64 = 134_345_473_332_450_000;
        b[60..68].copy_from_slice(&ft.to_le_bytes());
        let e = parse_entry(&b).unwrap();
        assert_eq!(e.run_count, 5);
        assert_eq!(e.last_exec_ft, Some(ft));
    }

    #[test]
    fn short_entry_is_none() {
        assert!(parse_entry(&[0u8; 16]).is_none());
    }

    #[test]
    fn ua_name_normalization() {
        // 普通路径：原样
        assert_eq!(
            normalize_ua_name(r"F:\ficlash\FlClash\FlClash.exe").as_deref(),
            Some(r"F:\ficlash\FlClash\FlClash.exe")
        );
        // System32 已知文件夹 GUID（Win+R/开始菜单启动系统程序的形态）→ 真实路径
        assert_eq!(
            normalize_ua_name(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe").as_deref(),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            normalize_ua_name(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\calc.exe").as_deref(),
            Some(r"C:\Windows\System32\calc.exe")
        );
        // 未知 GUID：原样保留（真实数据）
        assert_eq!(
            normalize_ua_name(r"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\x.lnk").as_deref(),
            Some(r"{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}\x.lnk")
        );
        // UWP AUMID：原样
        assert_eq!(
            normalize_ua_name("Microsoft.WindowsCalculator_8wekyb3d8bbwe!App").as_deref(),
            Some("Microsoft.WindowsCalculator_8wekyb3d8bbwe!App")
        );
        // 非程序杂项：丢弃
        assert_eq!(normalize_ua_name("Helper"), None);
    }

    #[test]
    #[ignore = "需要真实 HKU；本机执行 cargo test -- --ignored"]
    fn collector_reads_real_userassist() {
        let r = UserAssistCollector::default().run();
        assert!(r.count >= 1, "真实机器至少有一条 GUI 执行记录：{:?}", r.logs);
    }
}
