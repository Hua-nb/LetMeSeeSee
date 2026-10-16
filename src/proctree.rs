//! 进程树构建器：把**当前存活进程**（进程现场模块的快照）按 PPID 组织成
//! "谁启动了谁"的树——任务管理器/Process Explorer 的树形态。
//! 设计决策（2026-09-28 用户反馈定稿）：进程树只做现场视图；
//! 4688/Sysmon 的历史进程创建事件仍进时间线，但不再建树（历史多开机混杂，
//! 作为默认视图不直观）。
//! 种子经全局注册表（Mutex）投递：进程现场模块并行采集时 push，
//! scan_into 统一 commit 构建；分组重扫按模块替换缓存。

use crate::model::Sev;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;

/// 一个存活进程（来自现场快照）
#[derive(Debug, Clone)]
pub struct ProcSeed {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmd: String,
    /// 展示用本地时间
    pub start_display: String,
    /// 排序用的毫秒（0=未知）
    pub start_ms: i64,
    pub sev: Sev,
    pub tags: Vec<String>,
}

/// 输出的树节点（扁平+parent_key 引用，前端组装嵌套）
#[derive(Debug, Clone, Serialize)]
pub struct ProcNodeOut {
    pub key: String,
    #[serde(rename = "parentKey")]
    pub parent_key: String,
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmd: String,
    pub start: String,
    pub sev: Sev,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ProcTreeReport {
    /// live（有快照）| none（快照失败）
    pub tier: String,
    pub tier_note: String,
    pub coverage: String,
    pub nodes: Vec<ProcNodeOut>,
    pub orphan_count: usize,
}

/// 产生种子的模块（分组重扫时按组替换缓存）
const SEED_MODULES: &[(&str, &str)] = &[("进程现场", "现场快照（进程/网络）")];

struct Registry {
    /// 已提交：module_id → seeds
    store: HashMap<String, Vec<ProcSeed>>,
    /// 本次扫描待提交：(module_id, seed)
    pending: Vec<(String, ProcSeed)>,
}

fn registry() -> &'static Mutex<Registry> {
    static REG: std::sync::OnceLock<Mutex<Registry>> = std::sync::OnceLock::new();
    REG.get_or_init(|| {
        Mutex::new(Registry {
            store: HashMap::new(),
            pending: Vec::new(),
        })
    })
}

/// 模块采集时投递一条进程种子（线程安全）
pub fn push(module_id: &str, seed: ProcSeed) {
    if let Ok(mut r) = registry().lock() {
        r.pending.push((module_id.to_string(), seed));
    }
}

/// 全量扫描开始：清空全部种子
pub fn reset_all() {
    if let Ok(mut r) = registry().lock() {
        r.store.clear();
        r.pending.clear();
    }
}

/// 分组重扫开始：目标组内的种子模块缓存清空（重扫结果将替换）
pub fn reset_group(group: &str) {
    if let Ok(mut r) = registry().lock() {
        for (m, g) in SEED_MODULES {
            if *g == group {
                r.store.remove(*m);
            }
        }
        r.pending.clear();
    }
}

/// 扫描结束：把 pending 并入 store
fn commit_pending() {
    if let Ok(mut r) = registry().lock() {
        let pending = std::mem::take(&mut r.pending);
        for (m, s) in pending {
            r.store.entry(m).or_default().push(s);
        }
    }
}

/// 由当前种子构建进程树（scan_into 在模块执行后调用）
pub fn build_from_store() -> ProcTreeReport {
    commit_pending();
    let store = match registry().lock() {
        Ok(r) => r.store.clone(),
        Err(_) => return none_report(),
    };
    build(&store)
}

/// 构建核心（纯函数，便于隔离测试）：module_id → seeds
fn build(store: &HashMap<String, Vec<ProcSeed>>) -> ProcTreeReport {
    let seeds: Vec<&ProcSeed> = store
        .get("进程现场")
        .map(|v| v.iter().collect())
        .unwrap_or_default();
    if seeds.is_empty() {
        return none_report();
    }
    // key：pid:start_ms（快照内 PID 唯一，start 仅作排序辅助）
    let keys: Vec<String> = seeds
        .iter()
        .map(|s| format!("{}:{}", s.pid, s.start_ms))
        .collect();
    let mut parent_key = vec![String::new(); seeds.len()];
    let mut edge = vec!["none"; seeds.len()];
    // PID → 节点索引；存活快照内同 PID 唯一
    let mut by_pid: HashMap<u32, usize> = HashMap::new();
    for (i, s) in seeds.iter().enumerate() {
        if s.pid > 0 {
            by_pid.entry(s.pid).or_insert(i);
        }
    }
    for (i, s) in seeds.iter().enumerate() {
        if s.ppid == 0 {
            continue; // System Idle Process 等伪进程为根
        }
        if let Some(&pi) = by_pid.get(&s.ppid) {
            if pi != i {
                parent_key[i] = keys[pi].clone();
                edge[i] = "exact";
            }
        }
    }
    let valid_keys: std::collections::HashSet<&str> = keys.iter().map(|s| s.as_str()).collect();
    let mut orphan_count = 0usize;
    let mut nodes = Vec::with_capacity(seeds.len());
    for (i, s) in seeds.iter().enumerate() {
        if !parent_key[i].is_empty() && !valid_keys.contains(parent_key[i].as_str()) {
            parent_key[i].clear();
        }
        if parent_key[i].is_empty() && s.ppid != 0 {
            orphan_count += 1;
        }
        nodes.push(ProcNodeOut {
            key: keys[i].clone(),
            parent_key: parent_key[i].clone(),
            pid: s.pid,
            ppid: s.ppid,
            image: s.image.clone(),
            cmd: s.cmd.clone(),
            start: s.start_display.clone(),
            sev: s.sev,
            tags: s.tags.clone(),
        });
    }
    let times: Vec<i64> = seeds.iter().map(|s| s.start_ms).filter(|&t| t > 0).collect();
    let coverage = match (times.iter().min(), times.iter().max()) {
        (Some(&mn), Some(&mx)) => {
            let fmt = |ms: i64| {
                use chrono::TimeZone;
                chrono::Local
                    .timestamp_millis_opt(ms)
                    .single()
                    .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_default()
            };
            format!("存活进程启动时间 {} ~ {}", fmt(mn), fmt(mx))
        }
        _ => "（时间未知）".into(),
    };
    ProcTreeReport {
        tier: "live".into(),
        tier_note: format!(
            "当前存活进程 {} 个（扫描时刻快照，单次开机）。父已退出的进程为孤儿根——\
             开机临退的 smss 副本/userinit 等系统短命进程属正常。\
             4688/Sysmon 的历史进程创建事件见总时间线",
            nodes.len()
        ),
        coverage,
        nodes,
        orphan_count,
    }
}

fn none_report() -> ProcTreeReport {
    ProcTreeReport {
        tier: "none".into(),
        tier_note: "无法获取当前进程快照（PowerShell 不可用或超时）。".into(),
        coverage: String::new(),
        nodes: Vec::new(),
        orphan_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(pid: u32, ppid: u32, start_ms: i64, image: &str) -> ProcSeed {
        ProcSeed {
            pid,
            ppid,
            image: image.into(),
            cmd: String::new(),
            start_display: format!("t{start_ms}"),
            start_ms,
            sev: Sev::None,
            tags: vec![],
        }
    }

    fn live_store(seeds: Vec<ProcSeed>) -> HashMap<String, Vec<ProcSeed>> {
        HashMap::from([("进程现场".to_string(), seeds)])
    }

    #[test]
    fn live_tier_builds_ppid_chain() {
        let seeds = vec![
            seed(100, 0, 1000, r"C:\Windows\explorer.exe"),
            seed(200, 100, 2000, r"C:\Windows\System32\cmd.exe"),
            seed(300, 200, 3000, r"C:\Windows\System32\calc.exe"),
        ];
        let r = build(&live_store(seeds));
        assert_eq!(r.tier, "live");
        assert_eq!(r.nodes.len(), 3);
        let calc = r.nodes.iter().find(|n| n.pid == 300).unwrap();
        let cmd = r.nodes.iter().find(|n| n.pid == 200).unwrap();
        assert_eq!(calc.parent_key, cmd.key, "calc 应挂在 cmd 下");
        assert_eq!(r.orphan_count, 0);
    }

    #[test]
    fn live_orphan_parent_not_in_snapshot() {
        // 父已退出：快照中无此 PID → 孤儿（wininit 挂不到已退出的 smss 副本）
        let r = build(&live_store(vec![seed(300, 999, 3000, r"C:\x.exe")]));
        assert_eq!(r.tier, "live");
        assert_eq!(r.orphan_count, 1);
        assert!(r.nodes[0].parent_key.is_empty());
    }

    #[test]
    fn other_modules_seeds_ignored() {
        // 历史模式已移除：4688/Sysmon 的种子不再进树
        let mut store = live_store(vec![seed(100, 0, 1000, r"C:\a.exe")]);
        store.insert(
            "安全日志（Security）".into(),
            vec![seed(500, 4, 5000, r"C:\history.exe")],
        );
        let r = build(&store);
        assert_eq!(r.nodes.len(), 1);
        assert!(r.nodes[0].image.contains("a.exe"));
    }

    #[test]
    fn empty_store_is_none_tier() {
        assert_eq!(build(&HashMap::new()).tier, "none");
    }
}
