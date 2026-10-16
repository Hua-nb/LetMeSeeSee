//! 计划任务模块：递归解析 C:\Windows\System32\Tasks\**（无扩展名的 UTF-16 XML）。
//! 时间=任务 XML 的 RegistrationInfo/Date（任务注册时间，UTC，真实）；
//! 缺 Date 时回退文件修改时间并标注"近似"，绝不凭空造时间。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev};
use std::time::Instant;

pub const MODULE: &str = "计划任务";
const TASKS_ROOT: &str = r"C:\Windows\System32\Tasks";

const RAW_COLS: &[&str] = &["任务", "命令", "作者", "运行身份", "触发器", "注册时间"];

/// 任务文件字节 → 文本：BOM 判 UTF-16LE/BE，否则按 UTF-8（实测任务 XML 均为 UTF-16）
pub fn decode_task_xml(b: &[u8]) -> Option<String> {
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        let units: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return Some(String::from_utf16_lossy(&units));
    }
    if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
        let units: Vec<u16> = b[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        return Some(String::from_utf16_lossy(&units));
    }
    if b.starts_with(b"<") {
        return Some(String::from_utf8_lossy(b).to_string());
    }
    None
}

/// 提取所有 <tag>…</tag> 文本（支持 <tag attr="x"> 形式；任务 schema 目标元素无属性，
/// 兼容写法求稳）
pub fn extract_all(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(i) = xml[pos..].find(&open) {
        let start_all = pos + i;
        // 跳过属性到 '>'
        let Some(gt) = xml[start_all..].find('>') else { break };
        let content_start = start_all + gt + 1;
        if xml[start_all..content_start].ends_with('/') {
            // 自闭合 <tag/>
            pos = content_start;
            continue;
        }
        let Some(j) = xml[content_start..].find(&close) else { break };
        out.push(xml[content_start..content_start + j].trim().to_string());
        pos = content_start + j + close.len();
    }
    out
}

/// 触发器类型识别（开机/登录/日程等持久化关注点）
pub fn detect_triggers(xml: &str) -> Vec<&'static str> {
    let table = [
        ("<BootTrigger", "开机"),
        ("<LogonTrigger", "登录"),
        ("<CalendarTrigger", "日程"),
        ("<TimeTrigger", "定时"),
        ("<EventTrigger", "系统事件"),
        ("<IdleTrigger", "空闲"),
        ("<RegistrationTrigger", "注册时"),
    ];
    table
        .iter()
        .filter(|(pat, _)| xml.contains(pat))
        .map(|(_, name)| *name)
        .collect()
}

fn fmt_mtime(p: &std::path::Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?.modified().ok()?;
    Some(
        chrono::DateTime::<chrono::Local>::from(m)
            .format("%Y-%m-%d %H:%M:%S.000")
            .to_string(),
    )
}

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.filter_map(|e| e.ok()) {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

pub struct SchTasksCollector;

impl Default for SchTasksCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for SchTasksCollector {
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
        let mut files = Vec::new();
        walk(std::path::Path::new(TASKS_ROOT), &mut files);
        if files.is_empty() {
            logs.push("Tasks 目录不可读或为空（需管理员权限可读大部分任务）".into());
            return ModuleResult {
                module: self.id().into(),
                status: ModuleStatus::Warn,
                count: 0,
                duration_ms: t0.elapsed().as_millis(),
                logs,
                events,
                raw: None,
            };
        }
        let mut decode_fail = 0usize;
        let mut refs: Vec<String> = Vec::new();
        for f in &files {
            let Ok(bytes) = std::fs::read(f) else {
                decode_fail += 1; // 权限不足的个别任务文件
                continue;
            };
            let Some(xml) = decode_task_xml(&bytes) else {
                decode_fail += 1;
                continue;
            };
            let rel = f
                .strip_prefix(TASKS_ROOT)
                .unwrap_or(f)
                .to_string_lossy()
                .replace('\\', "/");
            // 任务名按 taskschd 惯例用反斜杠（文件系统 rel 是正斜杠）
            let name = rel.trim_end_matches(".xml").replace('/', "\\");

            let dates = extract_all(&xml, "Date");
            let authors = extract_all(&xml, "Author");
            let cmds = extract_all(&xml, "Command");
            let args = extract_all(&xml, "Arguments");
            let users = extract_all(&xml, "UserId");
            let triggers = detect_triggers(&xml);

            // Date 无时区后缀，任务 schema 规定为 UTC：补 Z 转本地
            let (time, time_src) = match dates.first().map(|d| {
                crate::timeutil::evtx_time_to_local(&format!("{d}Z"))
            }) {
                Some(Some(t)) => (t, "任务注册时间"),
                _ => match fmt_mtime(f) {
                    Some(t) => (t, "文件修改时间（近似）"),
                    None => ("（无时间戳）".into(), ""),
                },
            };
            let cmd_txt = if cmds.is_empty() {
                "（无 Exec 动作）".to_string()
            } else {
                cmds.iter()
                    .zip(args.iter().chain(std::iter::repeat(&String::new())))
                    .map(|(c, a)| if a.is_empty() { c.clone() } else { format!("{c} {a}") })
                    .collect::<Vec<_>>()
                    .join(" && ")
            };
            let mut info_parts = vec![cmd_txt.clone()];
            if let Some(a) = authors.first().filter(|a| !a.is_empty()) {
                info_parts.push(format!("作者 {a}"));
            }
            if let Some(u) = users.first().filter(|u| !u.is_empty()) {
                info_parts.push(format!("运行身份 {u}"));
            }
            if !triggers.is_empty() {
                info_parts.push(format!("触发：{}", triggers.join("/")));
            }
            info_parts.push(time_src.to_string());

            // 时间线降噪：\Microsoft 命名空间的系统任务（170+/242）只进原表；
            // 非微软任务才进时间线——应急关注的是新增/第三方任务。
            // 注意 name 无前导反斜杠（display 才补），此前写成 starts_with("\microsoft")
            // 永远不匹配，过滤从未生效
            let is_ms = name
                .to_ascii_lowercase()
                .starts_with(r"microsoft\");
            if !is_ms {
                events.push(ActivityEvent {
                    time: time.clone(),
                    kind: "计划任务".into(),
                    desc: format!("任务 \\{name}"),
                    info: info_parts.join(" · "),
                    module: MODULE.into(),
                    sev: Sev::None,
                    tags: vec![],
                });
            }
            rows.push(vec![
                format!("\\{name}"),
                cmd_txt,
                authors.first().cloned().unwrap_or_default(),
                users.first().cloned().unwrap_or_default(),
                triggers.join("/"),
                if time_src.is_empty() {
                    time
                } else {
                    format!("{time}（{time_src}）")
                },
            ]);
            refs.push(rel.replace('/', "\\")); // 任务相对路径 → /api/taskxml 读取完整 XML
        }
        logs.push(format!(
            "共 {} 个任务文件，解析 {} 条；时间线仅含非微软任务 {} 条（微软任务 {} 条见原表），失败/不可读 {} 个",
            files.len(),
            rows.len(),
            events.len(),
            rows.len() - events.len(),
            decode_fail
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
            raw: Some(RawTable {
                columns: RAW_COLS.iter().map(|s| s.to_string()).collect(),
                rows,
                refs,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        let mut v = vec![0xFF, 0xFE];
        for u in s.encode_utf16() {
            v.extend_from_slice(&u.to_le_bytes());
        }
        v
    }

    #[test]
    fn decodes_utf16_with_bom() {
        let b = utf16le(r#"<Task><A>x</A></Task>"#);
        assert_eq!(decode_task_xml(&b).unwrap(), r#"<Task><A>x</A></Task>"#);
    }

    #[test]
    fn decodes_plain_utf8() {
        assert_eq!(
            decode_task_xml(b"<Task><A>x</A></Task>").unwrap(),
            "<Task><A>x</A></Task>"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_task_xml(&[0x00, 0x01, 0x02]).is_none());
    }

    #[test]
    fn extracts_multiple_commands_with_args() {
        let xml = r#"<Actions><Exec><Command>powershell.exe</Command><Arguments>-enc AAA</Arguments></Exec>
<Exec><Command>cmd.exe</Command></Exec></Actions>"#;
        assert_eq!(
            extract_all(xml, "Command"),
            vec!["powershell.exe".to_string(), "cmd.exe".to_string()]
        );
        assert_eq!(extract_all(xml, "Arguments"), vec!["-enc AAA".to_string()]);
    }

    #[test]
    fn skips_self_closing_tags() {
        let xml = r#"<X><Date version="1">2026-01-02T03:04:05.1</Date><Y/></X>"#;
        assert_eq!(extract_all(xml, "Date").len(), 1);
        assert_eq!(extract_all(xml, "Y").len(), 0);
    }

    #[test]
    fn triggers_detected() {
        let xml = "<Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger><LogonTrigger/></Triggers>";
        assert_eq!(detect_triggers(xml), vec!["开机", "登录"]);
    }

    #[test]
    fn task_date_converts_utc_to_local() {
        // UTC 2019-09-18T18:27:49 → 本地必然同一天前後 24h 内
        let t = crate::timeutil::evtx_time_to_local("2019-09-18T18:27:49.0496979Z").unwrap();
        assert!(t.starts_with("2019-09-1"), "got {t}");
    }

    #[test]
    #[ignore = "真实任务目录；本机 cargo test -- --ignored"]
    fn collector_parses_real_tasks() {
        let r = SchTasksCollector::default().run();
        // 微软任务过滤修正后 count=非微软任务数（本机实测 28；干净系统低至十余个）
        assert!(r.count >= 15, "本机非微软任务应至少十余个：{:?}", r.logs);
        // 年份不得离谱（2194 类乱码）
        for e in &r.events {
            if e.time.len() >= 4 && e.time[..4].chars().all(|c| c.is_ascii_digit()) {
                assert!(&e.time[..4] <= "2027", "异常时间 {}", e.time);
            }
        }
    }
}
