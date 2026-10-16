use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, Sev};
use crate::regutil::{key_last_write, read_value, subkeys, HKEY};
use crate::shellitem::walk_items;
use std::time::Instant;

pub const MODULE: &str = "文件夹浏览记录（ShellBags）";

const MAX_DEPTH: usize = 15;
const MAX_NODES: usize = 20000;

/// BagMRU 树节点：item = 本节点的 ITEMIDLIST——存在【父键】里与本节点同编号的
/// REG_BINARY 值中（本机实测验证：新建文件夹的名字出现在父键的值[31]，
/// 同编号子键[31] 只持有 NodeSlot/MRUListEx 与下一层）
pub struct BagNode {
    pub item: Option<Vec<u8>>,
    /// 本节点注册表键的最后写入时间（真实系统记录）
    pub key_time: Option<String>,
    pub children: Vec<BagNode>,
}

/// 从路径拼装函数（纯函数，可测）：深度优先收集"有名字链"的路径
pub fn collect_paths(node: &BagNode) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    walk(node, &mut Vec::new(), &mut out);
    out
}

fn walk(node: &BagNode, prefix: &mut Vec<String>, out: &mut Vec<(String, Option<String>)>) {
    if out.len() >= MAX_NODES {
        return;
    }
    let mut my_name: Option<String> = None;
    if let Some(bytes) = &node.item {
        if let Some(items) = walk_items(bytes) {
            // 本节点的名称链：全部有名字的项拼起来（相对路径片段）
            let names: Vec<Option<String>> = items.iter().map(|i| i.name.clone()).collect();
            let joined = crate::modules::opensave::assemble_path(&names);
            if !joined.is_empty() {
                my_name = Some(joined);
            }
        }
    }
    let had_name = my_name.is_some();
    if let Some(n) = &my_name {
        prefix.push(n.clone());
    }
    // 有名字链且不是根 → 记录一条；时间=本节点键的最后写入（真实）
    if had_name && !prefix.is_empty() {
        let mut path = crate::modules::opensave::join_smart(prefix);
        // 无盘符/UNC 前缀的相对碎片：链挂在 BagMRU 树根（桌面命名空间）下，
        // 标注「桌面\」前缀，避免被误当作完整路径查找
        if !path.contains(r":\") && !path.starts_with(r"\\") {
            path = format!(r"桌面\{path}");
        }
        out.push((path, node.key_time.clone()));
    }
    for child in &node.children {
        if prefix.len() < MAX_DEPTH {
            walk(child, prefix, out);
        }
    }
    if had_name {
        prefix.pop();
    }
}

/// 递归加载 BagMRU 键树。
/// 结构（本机实测验证）：子键 i 的 ITEMIDLIST 存在【父键】的同编号值 i 里，
/// 子键自身持有 NodeSlot/MRUListEx 与下一层子键。
/// 旧版误读"本键值 0 = 本节点自己的名字"（实为第一个孩子的名字）——
/// 后果：所有叶子节点（占节点多数）永远无名被丢弃、已记录路径整体偏移一层。
fn load_tree(key_path: &str, depth: usize) -> BagNode {
    load_node(key_path, None, depth)
}

fn load_node(key_path: &str, my_item: Option<Vec<u8>>, depth: usize) -> BagNode {
    let key_time = key_last_write(HKEY::users(), key_path);
    let mut children = Vec::new();
    if depth < MAX_DEPTH {
        // 本键的编号值 = 各孩子的 ITEMIDLIST
        let mut child_items: std::collections::HashMap<String, Vec<u8>> =
            std::collections::HashMap::new();
        if let Ok(names) = crate::regutil::value_names(HKEY::users(), key_path) {
            for n in names {
                if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok((b, _)) = read_value(HKEY::users(), key_path, &n) {
                        child_items.insert(n, b);
                    }
                }
            }
        }
        if let Ok(subs) = subkeys(HKEY::users(), key_path) {
            for s in subs {
                // 子键名必须是数字（节点索引）
                if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
                    let item = child_items.get(&s).cloned();
                    children.push(load_node(&format!(r"{key_path}\{s}"), item, depth + 1));
                }
                if children.len() >= MAX_NODES {
                    break;
                }
            }
        }
    }
    BagNode { item: my_item, key_time, children }
}

/// 统计树的总节点数（用于日志解释"解出/未解出"的比例，不留静默缺口）
fn count_nodes(n: &BagNode) -> usize {
    1 + n.children.iter().map(count_nodes).sum::<usize>()
}

pub struct ShellBagsCollector;

impl Default for ShellBagsCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for ShellBagsCollector {
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
            // ProfileList → 用户主目录：把「桌面\」碎片还原成真实的桌面绝对路径
            let profile_desktop = crate::regutil::read_string_value(
                HKEY::local_machine(),
                &format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
                "ProfileImagePath",
            )
            .ok()
            // ProfileImagePath 常为 REG_EXPAND_SZ（%SystemDrive%\Users\x），须展开
            .map(|p| format!(r"{}\Desktop", crate::encoding::expand_env_vars(&p)));
            let roots = [
                format!(r"{sid}\Software\Microsoft\Windows\Shell\BagMRU"),
                // UsrClass.dat 挂载在 HKU\<sid>_Classes：文件夹浏览记录的大头在这里
                format!(
                    r"{sid}_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"
                ),
            ];
            for root in roots {
                if subkeys(HKEY::users(), &root).is_err() {
                    continue;
                }
                let root_time = key_last_write(HKEY::users(), &root);
                let tree = load_tree(&root, 0);
                let total = count_nodes(&tree);
                let paths = collect_paths(&tree);
                logs.push(format!(
                    "{sid}：{} 条文件夹路径（注册表节点 {} 个；其余 {} 个为虚拟位置/未知 SHITEMID 类型，按\"不猜名\"原则未列出）",
                    paths.len(),
                    total,
                    total.saturating_sub(paths.len())
                ));
                logs.push(
                    "说明：ShellBags 记录的是历史浏览——目录可能已被删除或改名；「桌面\\」碎片按用户主目录还原为绝对路径（前缀为推定）。时间=视图状态最后变动而非访问时间：重复访问旧文件夹不刷新其时间戳（只刷新祖先链），今天访问的旧文件夹仍显示首次留下视图状态的时间（实测：旧文件夹当天再开，Explorer 对其节点零写入）"
                        .into(),
                );
                for (path, time) in paths {
                    let (desc, extra) = match (&profile_desktop, path.strip_prefix(r"桌面\")) {
                        (Some(pd), Some(rest)) => (format!(r"{pd}\{rest}"), " · 前缀按用户桌面推定"),
                        _ => (path, ""),
                    };
                    // 存在性核验（用户底线要求：不存在的路径必须显式标注，绝不与
                    // 现存路径混排造成"捏造"观感）。UNC 路径不核验（网络查询可能阻塞）
                    let (exists_note, exists_suffix) = if desc.starts_with(r"\\") {
                        ("", "")
                    } else if std::path::Path::new(&desc).exists() {
                        ("", "")
                    } else {
                        (" · 路径已核验不存在（历史浏览记录，目录可能已被删除/移动/重命名）", "（已不存在）")
                    };
                    events.push(ActivityEvent {
                        time: time
                            .or_else(|| root_time.clone())
                            .unwrap_or_else(|| "（无时间戳）".into()),
                        kind: "浏览文件夹".into(),
                        desc: format!("{desc}{exists_suffix}"),
                        info: format!(
                            "ShellBags · 用户 {sid}{extra}{exists_note} · 时间=该节点注册表键的最后写入时间"
                        ),
                        module: MODULE.into(),
                        sev: Sev::None,
                        tags: vec![],
                    });
                }
            }
        }
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

    fn item_with_name(name: &str) -> Vec<u8> {
        // 按实测布局：0x31 头 12 字节 + ASCII 短名 + NUL
        let mut data = vec![0x31u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x58, 0x04, 0x66, 0x10, 0x00];
        data.extend_from_slice(name.as_bytes());
        data.push(0);
        // 完整 SHITEMID：cb 前缀 + 数据
        let mut pidl = ((data.len() + 2) as u16).to_le_bytes().to_vec();
        pidl.extend_from_slice(&data);
        pidl
    }

    #[test]
    fn collects_paths_recursively() {
        let tree = BagNode {
            item: None,
            key_time: None,
            children: vec![BagNode {
                item: Some({
                    // 卷项（无名）：cb=10 + 8 字节数据
                    let mut p = 10u16.to_le_bytes().to_vec();
                    p.extend_from_slice(&[0x2e, 0x80, 0x3a, 0xcc, 0xbf, 0xb4, 0x00, 0x00]);
                    p
                }),
                key_time: None,
                children: vec![BagNode {
                    item: Some(item_with_name("_proj")),
                    key_time: Some("2026-09-01 10:00:00.000".into()),
                    children: vec![BagNode {
                        item: Some(item_with_name("docs")),
                        key_time: None,
                        children: vec![],
                    }],
                }],
            }],
        };
        let paths = collect_paths(&tree);
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths[0].0.contains("_proj"));
        assert!(paths[1].0.contains("docs") && paths[1].0.contains("_proj"));
    }

    #[test]
    fn nameless_chain_records_nothing() {
        let mut p = 6u16.to_le_bytes().to_vec();
        p.extend_from_slice(&[0x2e, 0x80, 0x00, 0x00]);
        let tree = BagNode {
            item: Some(p),
            key_time: None,
            children: vec![],
        };
        assert!(collect_paths(&tree).is_empty());
    }

    #[test]
    #[ignore = "真实 HKCU；本机 cargo test -- --ignored"]
    fn collector_reads_real_shellbags() {
        let r = ShellBagsCollector::default().run();
        // 归属修正后（父键编号值=子节点身份），叶子节点可见：本机实测 2069→4636。
        // 阈值 4000：旧版（读本键值 0 当自己名字、叶子全丢）2069 条无法通过
        assert!(r.count >= 4000, "节点归属修正后应数千条：{:?}", r.logs);
        // 近期浏览的叶子节点必须可见（当天/近 30 天键写入）
        let recent = r
            .events
            .iter()
            .any(|e| e.time.starts_with("2026-") && e.time.as_str() >= "2026-09-16");
        assert!(recent, "近期浏览的文件夹（叶子节点）应可见：{:?}", r.logs);
    }
}
