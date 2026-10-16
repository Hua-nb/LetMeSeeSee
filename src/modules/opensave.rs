use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{key_last_write, read_value, subkeys, value_names, HKEY};
use crate::shellitem::walk_items;
use std::time::Instant;

pub const MODULE: &str = "文件对话框记录（OpenSave）";

pub fn assemble_path(names: &[Option<String>]) -> String {
    join_smart(
        &names
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>(),
    )
}

/// 展示用路径规整：无盘符/UNC 根的相对链标注「前缀未知」，
/// 避免被当成完整路径查找（对话框 PIDL 的根若是未注册 GUID 连接项则无法还原盘符）
pub fn display_path(p: &str) -> String {
    let t = p.trim();
    if t.contains(r":\") || t.starts_with(r"\\") {
        t.to_string()
    } else {
        format!("（前缀未知）{t}")
    }
}

/// 智能拼接路径段：上一段以 \ 结尾（如盘符 "D:\"、UNC "\\srv\share"）不再叠加分隔符
pub fn join_smart(parts: &[String]) -> String {
    let mut s = String::new();
    for p in parts {
        if s.is_empty() {
            s.push_str(p);
        } else if s.ends_with('\\') {
            s.push_str(p);
        } else {
            s.push('\\');
            s.push_str(p);
        }
    }
    s
}

pub struct OpenSaveCollector;

impl Default for OpenSaveCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for OpenSaveCollector {
    fn id(&self) -> &'static str {
        MODULE
    }

    fn group(&self) -> &'static str {
        "文件访问记录"
    }

    fn run(&self) -> ModuleResult {
        let t0 = Instant::now();
        let mut logs = Vec::new();
        let mut events = Vec::new();
        let sids = crate::regutil::user_sids();
        for sid in &sids {
            let root = format!(
                r"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
            );
            let Ok(buckets) = subkeys(HKEY::users(), &root) else {
                continue;
            };
            for ext in buckets {
                let key_path = format!(r"{root}\{ext}");
                let Ok(names) = value_names(HKEY::users(), &key_path) else {
                    continue;
                };
                // 键最后写入时间：该扩展对话框最近使用时间（降级时间源）
                let key_time = key_last_write(HKEY::users(), &key_path);
                let mut bucket_count = 0usize;
                for n in names.iter().filter(|n| n.as_str() != "MRUListEx") {
                    let Ok((bytes, _)) = read_value(HKEY::users(), &key_path, n) else {
                        continue;
                    };
                    if let Some(items) = walk_items(&bytes) {
                        let path = display_path(&assemble_path(
                            &items.iter().map(|i| i.name.clone()).collect::<Vec<_>>(),
                        ));
                        if path.is_empty() {
                            continue;
                        }
                        // 存在性核验（用户底线：不存在的路径必须显式标注，绝不与
                        // 现存路径混排）。仅核验有盘符前缀的路径；UNC 不核验
                        // （网络查询可能阻塞）；「前缀未知」非完整路径不核验
                        let (desc, exists_note) = if path.chars().nth(1) == Some(':') {
                            if std::path::Path::new(&path).exists() {
                                (path.clone(), "")
                            } else {
                                (
                                    format!("{path}（已不存在）"),
                                    " · 路径已核验不存在（历史对话框记录，文件可能已删除/移动/重命名或盘符变更）",
                                )
                            }
                        } else {
                            (path.clone(), "")
                        };
                        // 条目本身无结构化时间：用扩展键的注册表最后写入时间（真实系统记录）
                        events.push(ActivityEvent {
                            time: key_time
                                .clone()
                                .unwrap_or_else(|| "（无时间戳）".into()),
                            kind: "文件对话框".into(),
                            desc,
                            info: format!(
                                "打开/保存对话框 · 扩展名 {ext} · 用户 {sid} · 时间=该扩展键的注册表最后写入时间{exists_note}"
                            ),
                            module: MODULE.into(),
                            sev: Sev::None,
                            tags: vec![],
                        });
                        bucket_count += 1;
                    }
                }
                if bucket_count > 0 {
                    logs.push(format!("扩展名 {ext}：{bucket_count} 条"));
                }
            }
        }
        logs.insert(0, format!("共 {} 条打开/保存记录", events.len()));
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
    fn assembles_path_from_names() {
        let names = vec![None, None, Some("tools".into()), Some("gui_scan".into())];
        assert_eq!(assemble_path(&names), "tools\\gui_scan");
    }

    #[test]
    fn relative_paths_marked() {
        assert_eq!(
            display_path(r"geek\shellcode.bin"),
            "（前缀未知）geek\\shellcode.bin"
        );
        assert_eq!(display_path(r" D:\x\y "), r"D:\x\y"); // 绝对路径仅去空白
        assert_eq!(display_path(r"\\srv\share"), r"\\srv\share");
    }

    #[test]
    fn empty_names_give_empty_path() {
        assert_eq!(assemble_path(&[None, None]), "");
    }

    #[test]
    #[ignore = "真实 HKCU；本机 cargo test -- --ignored"]
    fn collector_reads_real_opensave() {
        let r = OpenSaveCollector::default().run();
        assert!(r.count >= 1, "{:?}", r.logs);
        // 真实机器：提取出的路径应包含盘符或可读名称
        for e in &r.events {
            assert!(!e.desc.trim().is_empty());
        }
    }
}
