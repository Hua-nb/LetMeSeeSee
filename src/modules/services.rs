//! 系统服务模块：HKLM\SYSTEM\CurrentControlSet\Services。
//! 只列出 ImagePath 位于 Windows 系统目录之外的条目（系统目录内为 OS 自带，全列会刷屏），
//! 可疑命中的（临时/公共目录、LOLBAS）由规则引擎标 R-011。
//! 时间=服务键最后写入时间（结构性真实来源）。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev};
use crate::regutil::{key_last_write, read_value, read_string_value, subkeys, HKEY};
use std::time::Instant;

pub const MODULE: &str = "系统服务";

const RAW_COLS: &[&str] = &["服务名", "ImagePath", "ServiceDll", "启动", "类型", "键最后写入时间"];

/// 规整 ImagePath：去引号、去 \??\ 前缀、展开 %SystemRoot%/%windir%/%SystemDrive%、
/// 补全相对路径（驱动常用 "System32\drivers\x.sys" / "\SystemRoot\..." 形式，大小写不定）
pub fn normalize_image_path(p: &str) -> String {
    let mut s = p.trim().trim_matches('"').to_string();
    if let Some(stripped) = s.strip_prefix(r"\??\") {
        s = stripped.to_string();
    }
    // \SystemRoot\xxx → 绝对路径（注册表里大小写不定，须忽略大小写匹配）
    let sr_env = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let b = s.as_bytes();
    if b.len() >= 12 && b[..12].eq_ignore_ascii_case(br"\SystemRoot\") {
        let (_, rest) = s.split_at(12);
        s = format!(r"{sr_env}\{rest}");
    }
    for pat in ["%systemroot%", "%windir%"] {
        s = replace_ci(&s, pat, &sr_env);
    }
    let sd = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    s = replace_ci(&s, "%systemdrive%", &sd);
    // 无盘符的相对路径（"system32\drivers\x.sys"）以系统根补全
    if !s.contains(r":\") && !s.starts_with(r"\\") {
        s = format!(r"{sr_env}\{s}");
    }
    s
}

fn replace_ci(hay: &str, pat: &str, to: &str) -> String {
    let lh = hay.to_ascii_lowercase();
    let lp = pat.to_ascii_lowercase();
    let mut out = String::new();
    let mut pos = 0;
    while let Some(i) = lh[pos..].find(&lp) {
        out.push_str(&hay[pos..pos + i]);
        out.push_str(to);
        pos += i + lp.len();
    }
    out.push_str(&hay[pos..]);
    out
}

/// 是否 Windows 系统目录内（含 system32/驱动仓库），这些不列入时间线
pub fn is_system_dir(p: &str) -> bool {
    let l = normalize_image_path(p).to_ascii_lowercase();
    l.starts_with(r"c:\windows\") || l == r"c:\windows"
}

/// Start 值语义
pub fn start_name(start: u32) -> &'static str {
    match start {
        0 => "引导启动(驱动)",
        1 => "系统启动(驱动)",
        2 => "自动",
        3 => "手动",
        4 => "已禁用",
        _ => "未知",
    }
}

/// Type 值语义（1/2 内核与文件系统驱动，8/16/32 服务）
pub fn type_name(t: u32) -> &'static str {
    match t {
        1 => "内核驱动",
        2 => "文件系统驱动",
        8 => "系统服务",
        16 | 32 => "应用程序服务",
        _ => "其他",
    }
}

fn read_dword(path: &str, value: &str) -> Option<u32> {
    let (b, _) = read_value(HKEY::local_machine(), path, value).ok()?;
    let a: [u8; 4] = b.try_into().ok()?;
    Some(u32::from_le_bytes(a))
}

pub struct ServicesCollector;

impl Default for ServicesCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for ServicesCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "入侵痕迹排查"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let mut rows: Vec<Vec<String>> = Vec::new();
        let base = r"SYSTEM\CurrentControlSet\Services";
        let Ok(names) = subkeys(HKEY::local_machine(), base) else {
            logs.push("Services 键不可读".into());
            return ModuleResult {
                module: self.id().into(),
                status: ModuleStatus::Err,
                count: 0,
                duration_ms: t0.elapsed().as_millis(),
                logs,
                events,
                raw: None,
            };
        };
        let total = names.len();
        let mut listed = 0usize;
        let mut svc_dll_hits = 0usize;
        for name in names {
            let key_path = format!(r"{base}\{name}");
            let image = read_string_value(HKEY::local_machine(), &key_path, "ImagePath").ok();
            // svchost 共享进程服务的真实载荷在 Parameters\ServiceDll——
            // ImagePath 指向系统目录的 svchost.exe 不代表无害，ServiceDll
            // 指向系统目录之外才是需要列出的（经典无文件服务持久化落点）
            let service_dll = read_string_value(
                HKEY::local_machine(),
                &format!(r"{key_path}\Parameters"),
                "ServiceDll",
            )
            .ok();
            let image_out = image
                .as_deref()
                .filter(|s| !s.trim().is_empty() && !is_system_dir(s));
            let dll_out = service_dll
                .as_deref()
                .filter(|s| !s.trim().is_empty() && !is_system_dir(s));
            if image_out.is_none() && dll_out.is_none() {
                continue; // 映像与 ServiceDll 均在系统目录内（或无）→ OS 自带
            }
            let start = read_dword(&key_path, "Start").unwrap_or(3);
            let typ = read_dword(&key_path, "Type").unwrap_or(0x10);
            let norm_img = image_out.map(normalize_image_path);
            let norm_dll = dll_out.map(normalize_image_path);
            let time = key_last_write(HKEY::local_machine(), &key_path)
                .unwrap_or_else(|| "（无时间戳）".into());
            let (desc, payload) = match (&norm_img, &norm_dll) {
                (Some(img), Some(dll)) => (
                    format!("服务 {name}（{}，含 ServiceDll）", start_name(start)),
                    format!("{img} · ServiceDll {dll}"),
                ),
                (Some(img), None) => (
                    format!("服务 {name}（{}）", start_name(start)),
                    img.clone(),
                ),
                (None, Some(dll)) => {
                    svc_dll_hits += 1;
                    (
                        format!("服务 {name}（{}，svchost 服务DLL）", start_name(start)),
                        format!("ServiceDll {dll} · ImagePath 在系统目录内"),
                    )
                }
                (None, None) => unreachable!(),
            };
            events.push(ActivityEvent {
                time: time.clone(),
                kind: "系统服务".into(),
                desc,
                info: format!("{payload} · {} · 键最后写入时间", type_name(typ)),
                module: MODULE.into(),
                sev: Sev::None,
                tags: vec![],
            });
            rows.push(vec![
                name.clone(),
                norm_img.unwrap_or_default(),
                norm_dll.unwrap_or_default(),
                start_name(start).into(),
                type_name(typ).into(),
                time,
            ]);
            listed += 1;
        }
        logs.push(format!(
            "共 {total} 个服务/驱动，{listed} 个映像/ServiceDll 位于系统目录之外已列入时间线（其中 svchost ServiceDll {svc_dll_hits} 个）"
        ));
        ModuleResult {
            module: self.id().into(),
            status: if listed == 0 {
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

    #[test]
    fn normalizes_paths() {
        assert_eq!(
            normalize_image_path(r#""C:\Program Files\x\svc.exe""#),
            r"C:\Program Files\x\svc.exe"
        );
        assert_eq!(normalize_image_path(r"\??\C:\x\drv.sys"), r"C:\x\drv.sys");
        // SystemRoot 展开跟随本机环境变量，仅断言忽略大小写后的结果
        let n = normalize_image_path("%SystemRoot%\\sys.exe");
        assert_eq!(n.to_ascii_lowercase(), r"c:\windows\sys.exe");
        // 驱动常用相对/替代前缀形式（大小写不定）
        assert!(is_system_dir("System32\\drivers\\nvlddmkm.sys"));
        assert!(is_system_dir(r"\SystemRoot\System32\drivers\x.sys"));
        assert!(is_system_dir(r"\systemroot\system32\x.sys"));
        assert!(is_system_dir("%windir%\\system32\\svchost.exe -k netsvcs"));
        assert!(!is_system_dir("F:\\Marvis\\marvis\\svc.exe"));
    }

    #[test]
    fn system_dir_detection() {
        assert!(is_system_dir(r"C:\Windows\System32\svchost.exe"));
        assert!(is_system_dir(r"%SystemRoot%\System32\drivers\k.sys"));
        assert!(!is_system_dir(r"C:\Program Files\Vendor\svc.exe"));
        assert!(!is_system_dir(r"C:\Users\Public\x.exe"));
    }

    #[test]
    fn start_and_type_names() {
        assert_eq!(start_name(2), "自动");
        assert_eq!(start_name(4), "已禁用");
        assert_eq!(type_name(16), "应用程序服务");
        assert_eq!(type_name(1), "内核驱动");
    }

    #[test]
    #[ignore = "真实注册表；本机 cargo test -- --ignored"]
    fn collector_lists_nonsystem_services() {
        let r = ServicesCollector::default().run();
        assert!(r.count >= 10, "本机应有数十个非系统目录服务：{:?}", r.logs);
        assert!(r.events.iter().all(|e| !is_system_dir(&e.info)));
    }
}
