use serde::{Deserialize, Serialize};

/// 可疑等级：None=无标记，Gray=信息提示，Yellow=关注，Red=高危
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Sev {
    None,
    Gray,
    Yellow,
    Red,
}

/// 一条可疑标记（M3 挂规则引擎，M1 结构就位）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub sev: Sev,
    pub text: String,
}

/// 统一时间线记录，所有模块产出此结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEvent {
    /// 本地时间 "YYYY-MM-DD HH:MM:SS.mmm"
    pub time: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub desc: String,
    pub info: String,
    pub module: String,
    pub sev: Sev,
    pub tags: Vec<Tag>,
}

impl ActivityEvent {
    pub fn plain(time: String, kind: &str, desc: String, info: String, module: &str) -> Self {
        Self {
            time,
            kind: kind.into(),
            desc,
            info,
            module: module.into(),
            sev: Sev::None,
            tags: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleStatus {
    Ok,
    Warn,
    Err,
}

/// 单个采集模块的完整产出（内部用）
#[derive(Debug, Serialize)]
pub struct ModuleResult {
    pub module: String,
    pub status: ModuleStatus,
    pub count: usize,
    pub duration_ms: u128,
    pub logs: Vec<String>,
    pub events: Vec<ActivityEvent>,
    /// 模块专用原表视图（如注册表自启动/用户表/计划任务清单）；时间线本位模块为 None
    pub raw: Option<RawTable>,
}

/// 结构化原表：列名 + 全字符串行（前端零转换直接渲染）
/// refs：与行等长的引用（如任务相对路径），前端据此提供"查看详情"；空=无
#[derive(Debug, Clone, Serialize)]
pub struct RawTable {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub refs: Vec<String>,
}

/// 报告中携带的模块原表（module → table）
#[derive(Debug, Clone, Serialize)]
pub struct ModuleTable {
    pub module: String,
    pub table: RawTable,
}

/// 模块页展示用摘要（不含明细事件）
#[derive(Debug, Clone, Serialize)]
pub struct ModuleSummary {
    pub module: String,
    /// 所属问题域大类（程序运行记录/文件访问记录/系统与软件事件/安全日志/PowerShell 日志）
    pub group: String,
    pub status: ModuleStatus,
    pub count: usize,
    pub duration_ms: u128,
    pub logs: Vec<String>,
    /// 本模块数据最近一次采集完成时刻（HH:MM:SS）——分组重扫时各模块新鲜度不同，
    /// 全局单一"数据截至"会误导，前端按当前选中模块显示
    pub scanned_at: String,
    /// 隐藏模块：不进侧边栏（数据源仍运行、事件仍进时间线）。
    /// 进程现场即此列——展示职责已由进程树页承接
    pub hidden: bool,
}

/// 可疑规则信息（含命中数）
#[derive(Debug, Clone, Serialize)]
pub struct RuleInfo {
    pub id: String,
    pub sev: Sev,
    pub name: String,
    pub detail: String,
    pub hits: usize,
}

/// 采集环境信息（随报告输出，构成证据链要素）
#[derive(Debug, Clone, Serialize)]
pub struct SysInfo {
    pub hostname: String,
    pub os_version: String,
    /// 扫描完成时刻（本地时间）
    pub scan_time: String,
    pub elevated: bool,
    pub tool_version: String,
}

/// 一次完整扫描的输出：合并时间线 + 模块摘要 + 规则命中 + 模块原表
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub events: Vec<ActivityEvent>,
    pub modules: Vec<ModuleSummary>,
    pub rules: Vec<RuleInfo>,
    /// 模块专用原表视图（自启动/用户表/任务清单等）
    pub tables: Vec<ModuleTable>,
    /// 是否以管理员运行（影响 Prefetch/Security/BAM/AmCache 可用性）
    pub elevated: bool,
    /// 采集环境（主机/系统版本/扫描时间/工具版本）
    pub sysinfo: SysInfo,
    /// 进程树（Sysmon/4688/现场快照三档降级；详见 proctree.rs）
    pub proc_tree: crate::proctree::ProcTreeReport,
}

/// 采集模块统一接口。Send+Sync：模块间并行采集（std::thread::scope）所需
pub trait Collector: Send + Sync {
    fn id(&self) -> &'static str;
    /// 所属问题域大类（侧边栏分组+分组重扫用）
    fn group(&self) -> &'static str;
    /// 隐藏模块（不进侧边栏；仍采集、事件仍进时间线）
    fn hidden(&self) -> bool {
        false
    }
    fn run(&self) -> ModuleResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sev_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Sev::None).unwrap(), "\"none\"");
        assert_eq!(serde_json::to_string(&Sev::Red).unwrap(), "\"red\"");
    }

    #[test]
    fn plain_event_maps_fields() {
        let e = ActivityEvent::plain(
            "2026-09-22 18:42:13.245".into(),
            "系统启动",
            "事件日志服务已启动（开机）".into(),
            "System 6005".into(),
            "事件日志 System",
        );
        let j: serde_json::Value = serde_json::to_value(&e).unwrap();
        assert_eq!(j["type"], "系统启动");
        assert_eq!(j["module"], "事件日志 System");
        assert_eq!(j["sev"], "none");
        assert_eq!(j["tags"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn module_summary_carries_logs() {
        let s = ModuleSummary {
            module: "事件日志 System".into(),
            group: "系统与软件事件".into(),
            status: ModuleStatus::Ok,
            count: 42,
            duration_ms: 120,
            logs: vec!["解析 12000 条".into()],
            scanned_at: "10:00:00".into(),
            hidden: false,
        };
        let j: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(j["status"], "ok");
        assert_eq!(j["logs"][0], "解析 12000 条");
    }

    #[test]
    fn raw_table_serializes_columns_and_rows() {
        let t = RawTable {
            columns: vec!["账户".into(), "RID".into()],
            rows: vec![vec!["Administrator".into(), "500".into()]],
            refs: vec![],
        };
        let j: serde_json::Value = serde_json::to_value(&t).unwrap();
        assert_eq!(j["columns"][0], "账户");
        assert_eq!(j["rows"][0][1], "500");
    }
}
