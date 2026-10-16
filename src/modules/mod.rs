pub mod evtx_system;
pub mod evtx_powershell;
pub mod evtx_security;
pub mod muicache;
pub mod prefetch;
pub mod amcache;
pub mod crashes;
pub mod software;
pub mod opensave;
pub mod recentdocs;
pub mod shellbags;
pub mod bam;
pub mod shimcache;
pub mod userassist;
pub mod autostart;
pub mod schtasks;
pub mod services;
pub mod wmi_sub;
pub mod account;
pub mod usb;
pub mod live_proc;
pub mod live_net;
pub mod advpersist;
pub mod defender;
pub mod rdpclient;
pub mod recyclebin;
pub mod dropped;
pub mod sysmon;

use crate::model::{
    ActivityEvent, Collector, ModuleResult, ModuleSummary, ModuleTable, ScanReport, SysInfo,
};

/// 采集环境信息（证据链要素：谁、哪台机器、什么系统、何时、用什么版本采的）
pub fn collect_sysinfo(elevated: bool) -> SysInfo {
    let hostname =
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "(未知主机名)".into());
    let ver_root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let product = crate::regutil::read_string_value(
        crate::regutil::HKEY::local_machine(),
        ver_root,
        "ProductName",
    )
    .unwrap_or_default();
    let display = crate::regutil::read_string_value(
        crate::regutil::HKEY::local_machine(),
        ver_root,
        "DisplayVersion",
    )
    .or_else(|_| {
        crate::regutil::read_string_value(
            crate::regutil::HKEY::local_machine(),
            ver_root,
            "ReleaseId",
        )
    })
    .unwrap_or_default();
    let build = crate::regutil::read_string_value(
        crate::regutil::HKEY::local_machine(),
        ver_root,
        "CurrentBuildNumber",
    )
    .unwrap_or_default();
    let os_version = format!("{product} {display} (Build {build})")
        .trim()
        .to_string();
    SysInfo {
        hostname,
        os_version,
        scan_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        elevated,
        tool_version: env!("CARGO_PKG_VERSION").into(),
    }
}

pub fn all_modules() -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(evtx_system::EvtxSystemCollector::default()),
        Box::new(userassist::UserAssistCollector::default()),
        Box::new(bam::BamCollector::default()),
        Box::new(shimcache::ShimCacheCollector::default()),
        Box::new(amcache::AmCacheCollector::default()),
        Box::new(opensave::OpenSaveCollector::default()),
        Box::new(shellbags::ShellBagsCollector::default()),
        Box::new(recentdocs::RecentDocsCollector::default()),
        Box::new(software::SoftwareCollector::default()),
        Box::new(crashes::CrashesCollector::default()),
        Box::new(prefetch::PrefetchCollector::default()),
        Box::new(muicache::MuiCacheCollector::default()),
        Box::new(evtx_security::SecurityCollector::default()),
        Box::new(evtx_powershell::PowerShellCollector::default()),
        Box::new(autostart::AutoStartCollector::default()),
        Box::new(schtasks::SchTasksCollector::default()),
        Box::new(services::ServicesCollector::default()),
        Box::new(wmi_sub::WmiSubCollector::default()),
        Box::new(account::AccountCollector::default()),
        Box::new(usb::UsbCollector::default()),
        Box::new(advpersist::AdvPersistCollector::default()),
        Box::new(defender::DefenderCollector::default()),
        Box::new(rdpclient::RdpClientCollector::default()),
        Box::new(recyclebin::RecycleBinCollector::default()),
        Box::new(dropped::DroppedCollector::default()),
        Box::new(live_proc::LiveProcCollector::default()),
        Box::new(live_net::LiveNetCollector::default()),
        Box::new(sysmon::SysmonCollector::default()),
    ]
}

pub fn run_scan() -> ScanReport {
    let mut cache: Option<ScanReport> = None;
    scan_into(&mut cache, None)
}

/// 全量或分组扫描；分组结果合并进缓存后整体返回（其他组数据不丢失）。
/// 模块间并行采集（各自只读系统状态、互不依赖）：全量 wall 时间 ≈ 最慢单模块，
/// 而非各模块耗时之和。分组重扫只重跑目标组的模块。
pub fn scan_into(cached: &mut Option<ScanReport>, group: Option<&str>) -> ScanReport {
    let mut all_events: Vec<ActivityEvent> = Vec::new();
    let mut modules: Vec<ModuleSummary> = Vec::new();
    let mut tables: Vec<ModuleTable> = Vec::new();
    // 进程树种子：全量清空 / 分组重扫只清目标组（与原表缓存同语义）
    match group {
        None => crate::proctree::reset_all(),
        Some(g) => crate::proctree::reset_group(g),
    }
    // 分组重扫：保留其他组的旧数据，只重跑目标组
    if let (Some(c), Some(g)) = (cached.as_ref(), group) {
        // 目标组的模块名单：这些模块的原表将被重跑结果替换
        let target_names: Vec<&str> = all_modules()
            .iter()
            .filter(|m| m.group() == g)
            .map(|m| m.id())
            .collect();
        for m in &c.modules {
            if m.group != g {
                all_events.extend(c.events.iter().filter(|e| e.module == m.module).cloned());
                modules.push(m.clone());
            }
        }
        tables.extend(
            c.tables
                .iter()
                .filter(|t| !target_names.contains(&t.module.as_str()))
                .cloned(),
        );
    }
    let targets: Vec<Box<dyn Collector>> = all_modules()
        .into_iter()
        .filter(|m| group.map_or(true, |g| m.group() == g))
        .collect();
    // 并行执行：27 个模块并发，顺序保持 all_modules() 原序（侧边栏/摘要稳定）
    let results: Vec<ModuleResult> = std::thread::scope(|scope| {
        let handles: Vec<_> = targets.iter().map(|m| scope.spawn(|| m.run())).collect();
        handles
            .into_iter()
            .zip(targets.iter())
            .map(|(h, m)| match h.join() {
                Ok(r) => r,
                Err(_) => ModuleResult {
                    // release 为 panic=abort，此分支仅 debug（unwind）可达
                    module: m.id().into(),
                    status: crate::model::ModuleStatus::Err,
                    count: 0,
                    duration_ms: 0,
                    logs: vec!["模块线程崩溃（panic）".into()],
                    events: Vec::new(),
                    raw: None,
                },
            })
            .collect()
    });
    let scanned_at = chrono::Local::now().format("%H:%M:%S").to_string();
    for r in results {
        all_events.extend(r.events.iter().cloned());
        if let Some(t) = r.raw {
            tables.push(ModuleTable {
                module: r.module.clone(),
                table: t,
            });
        }
        modules.push(ModuleSummary {
            module: r.module.clone(),
            group: group_of_by_id(&r.module).to_string(),
            status: r.status,
            count: r.count,
            duration_ms: r.duration_ms,
            logs: r.logs,
            scanned_at: scanned_at.clone(),
            hidden: targets
                .iter()
                .find(|m| m.id() == r.module)
                .map(|m| m.hidden())
                .unwrap_or(false),
        });
    }
    // Prefetch 禁用检测 → 灰色证据缺失提示（R-009）。
    // 仅在全量或目标组为"程序运行记录"时追加：分组重扫其他组时，旧提示已随
    // 缓存保留，无条件追加会造成重复
    let prefetch_group = "程序运行记录";
    if group.map_or(true, |g| g == prefetch_group) {
        let prefetch_disabled = crate::regutil::read_value(
            crate::regutil::HKEY::local_machine(),
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters",
            "EnablePrefetcher",
        )
        .ok()
        .and_then(|(b, _)| b.try_into().ok().map(|v: [u8; 4]| u32::from_le_bytes(v)))
        .map(|v| v == 0)
        .unwrap_or(false)
            || match std::fs::read_dir(r"C:\Windows\Prefetch") {
                Ok(d) => d.filter_map(|e| e.ok()).count() == 0,
                Err(_) => true, // 枚举被拒同样意味着该证据源缺失
            };
        if prefetch_disabled {
            all_events.push(ActivityEvent {
                time: "（无时间戳）".into(),
                kind: "证据提示".into(),
                desc: "Prefetch 已禁用/为空或不可读，程序执行证据可能缺失".into(),
                info: "EnablePrefetcher=0 · 由四件套其他模块补充覆盖".into(),
                module: "程序预读取（Prefetch）".into(),
                sev: crate::model::Sev::Gray,
                tags: vec![crate::model::Tag {
                    sev: crate::model::Sev::Gray,
                    text: "R-009 证据缺失提示".into(),
                }],
            });
        }
    }

    let rules = crate::suspicion::apply_rules(&mut all_events);
    all_events.sort_by(|a, b| b.time.cmp(&a.time));
    let elevated = crate::regutil::is_elevated();
    let proc_tree = crate::proctree::build_from_store();
    let report = ScanReport {
        events: all_events,
        modules,
        rules,
        tables,
        elevated,
        sysinfo: collect_sysinfo(elevated),
        proc_tree,
    };
    *cached = Some(report.clone());
    report
}

/// 模块 id（MODULE 常量）→ 所属大类；未知 id 原样返回
fn group_of_by_id(module_id: &str) -> &str {
    all_modules()
        .into_iter()
        .find(|m| m.id() == module_id)
        .map(|m| m.group())
        .unwrap_or("")
}

/// 测试辅助：用事件注入替代真实采集，验证合并/排序/摘要逻辑
pub fn run_scan_with(inject: impl Fn(&std::path::Path) -> Vec<ActivityEvent>) -> ScanReport {
    let mut events = inject(std::path::Path::new(""));
    events.sort_by(|a, b| b.time.cmp(&a.time));
    ScanReport {
        modules: vec![ModuleSummary {
            module: evtx_system::MODULE.into(),
            group: "系统与软件事件".into(),
            count: events.len(),
            status: crate::model::ModuleStatus::Ok,
            duration_ms: 0,
            logs: vec!["注入模式（测试）".into()],
            scanned_at: chrono::Local::now().format("%H:%M:%S").to_string(),
            hidden: false,
        }],
        events,
        rules: Vec::new(),
        tables: Vec::new(),
        elevated: crate::regutil::is_elevated(),
        sysinfo: collect_sysinfo(crate::regutil::is_elevated()),
        proc_tree: crate::proctree::ProcTreeReport::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "真实全量+分组扫描；本机 cargo test -- --ignored"]
    fn group_rescan_merges_without_duplicates() {
        // 全量 → 连续两次分组重扫：模块数恒定、R-009 灰提示不重复累加
        let mut cached: Option<ScanReport> = None;
        let full = scan_into(&mut cached, None);
        let n_modules = full.modules.len();
        let r009 = |r: &ScanReport| {
            r.events
                .iter()
                .filter(|e| e.tags.iter().any(|t| t.text.starts_with("R-009")))
                .count()
        };
        let base_r009 = r009(&full);
        let g1 = scan_into(&mut cached, Some("入侵痕迹排查"));
        assert_eq!(g1.modules.len(), n_modules, "分组重扫后模块数应保持不变");
        assert_eq!(r009(&g1), base_r009, "重扫他组时 R-009 不得重复追加");
        let g2 = scan_into(&mut cached, Some("程序运行记录"));
        assert_eq!(g2.modules.len(), n_modules);
        assert_eq!(r009(&g2), base_r009, "重扫 Prefetch 所在组时 R-009 不得重复");
        // 缓存合并：未重扫组的事件仍在
        assert!(g2.events.iter().any(|e| e.module.contains("WMI")));
        // 摘要携带采集时间
        assert!(g2.modules.iter().all(|m| m.scanned_at.contains(':')));
    }

    #[test]
    fn all_modules_have_unique_ids() {
        let mods = all_modules();
        let mut ids: Vec<&str> = mods.iter().map(|m| m.id()).collect();
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n, "模块 id 不得重复（缓存按 module 名合并）");
    }
}
