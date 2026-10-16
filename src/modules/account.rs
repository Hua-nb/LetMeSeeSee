//! 账号安全模块：直接解析 C:\Windows\System32\config\SAM（需管理员）。
//! 检出三类入侵痕迹：$ 尾隐藏账号、RID 500 克隆账户、多名称映射同一 RID。
//! 时间=SAM 用户键最后写入时间（≈账号创建/最后修改，如实标注）。
//! Names\<名称> 键默认值中的 RID 无公开稳定偏移，采用"在已知 RID 集合内匹配"
//! 的自校验提取方式。

use crate::model::{ActivityEvent, Collector, ModuleResult, ModuleStatus, RawTable, Sev, Tag};
use crate::timeutil::filetime_to_local;
use regf_rs::{Hive, RegValue};
use std::time::Instant;

pub const MODULE: &str = "账号安全";
const SAM_PATH: &str = r"C:\Windows\System32\config\SAM";
const REGF_BASE_BLOCK: usize = 4096;

/// 取得 SAM hive 字节：直读 → （提权时）reg save HKLM\SAM 导出副本。
/// SAM 常被系统独占锁住，直读即使管理员也可能失败；reg save 走备份语义可绕开。
fn acquire_sam(logs: &mut Vec<String>) -> Option<Vec<u8>> {
    match std::fs::read(SAM_PATH) {
        Ok(b) => {
            logs.push("直接读取 SAM 成功".into());
            return Some(b);
        }
        Err(e) => logs.push(format!("直接读取 SAM 失败（{e}），尝试 RegSaveKeyEx 导出副本…")),
    }
    if !crate::regutil::is_elevated() {
        return None;
    }
    let tmp = std::env::temp_dir().join("LetMeSeeSee-SAM.hiv");
    match crate::winapi::save_registry_key("HKLM", "SAM", tmp.to_string_lossy().as_ref()) {
        Ok(()) => {
            let b = std::fs::read(&tmp).ok();
            let _ = std::fs::remove_file(&tmp);
            if b.is_some() {
                logs.push("已通过 RegSaveKeyEx 导出副本读取".into());
            }
            b
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            logs.push(format!("SAM 备份失败：{e}"));
            None
        }
    }
}

#[derive(Debug)]
pub struct AcctInfo {
    pub name: String,
    pub rid: u32,
    pub key_ft: Option<u64>,
}

/// 从 Names\<名称> 键默认值二进制块中匹配已知 RID（布局无公开稳定偏移，集合匹配自校验）
pub fn rid_from_names_blob(blob: &[u8], known: &[u32]) -> Option<u32> {
    if blob.len() < 4 {
        return None;
    }
    for i in 0..=(blob.len() - 4) {
        let v = u32::from_le_bytes(blob[i..i + 4].try_into().ok()?);
        if known.contains(&v) && v > 0 {
            // 偏移 0 是类别标记，RID 通常在偏移 4，扫到即用首个匹配
            return Some(v);
        }
    }
    None
}

/// 账号定级：$ 尾隐藏 / RID 500 非 Administrator / 同 RID 多名称
pub fn account_notes(name: &str, rid: u32, all: &[AcctInfo]) -> Vec<&'static str> {
    let mut notes = Vec::new();
    if name.ends_with('$') {
        notes.push("隐藏账号（$ 结尾，net user 默认不显示）");
    }
    if rid == 500 && !name.eq_ignore_ascii_case("Administrator") {
        notes.push("RID 500 克隆管理员");
    }
    let dup = all
        .iter()
        .any(|a| a.rid == rid && !a.name.eq_ignore_ascii_case(name));
    if dup {
        notes.push("与其他账号共享同一 RID（克隆特征）");
    }
    notes
}

fn nk_timestamp(hive_bytes: &[u8], node_offset: u32) -> Option<u64> {
    let start = REGF_BASE_BLOCK + node_offset as usize + 8;
    let b = hive_bytes.get(start..start + 8)?;
    let ft = u64::from_le_bytes(b.try_into().ok()?);
    (ft > 0).then_some(ft)
}

/// 从已加载的 SAM hive 提取账号清单（Users\00000XXX 键名=RID 十六进制）
pub fn collect_accounts(hive: &Hive, hive_bytes: &[u8]) -> Vec<AcctInfo> {
    // 真实 SAM 根键名为 "SAM"；兼容直接以 "Domains" 开头的写法
    let users_path = match (
        hive.list_subkeys(r"SAM\Domains\Account\Users"),
        hive.list_subkeys(r"Domains\Account\Users"),
    ) {
        (Ok(k), _) if !k.is_empty() => (r"SAM\Domains\Account\Users", k),
        (_, Ok(k)) if !k.is_empty() => (r"Domains\Account\Users", k),
        _ => return Vec::new(),
    };
    let names_path = format!(r"{}\Names", users_path.0.replace(r"\Users", ""));

    // RID 键名 "000003E8" → RID；同时记录键时间戳
    let mut rid_keys: Vec<(u32, &str)> = Vec::new();
    let mut rid_ft: Vec<(u32, Option<u64>)> = Vec::new();
    for k in &users_path.1 {
        let Ok(rid) = u32::from_str_radix(k, 16) else {
            continue;
        };
        rid_keys.push((rid, k));
        let ft = hive
            .open(&format!(r"{}\{k}", users_path.0))
            .ok()
            .and_then(|n| nk_timestamp(hive_bytes, n.offset()));
        rid_ft.push((rid, ft));
    }
    let known: Vec<u32> = rid_keys.iter().map(|(r, _)| *r).collect();

    let mut out = Vec::new();
    if let Ok(names) = hive.list_subkeys(&names_path) {
        for n in names {
            let path = format!(r"{names_path}\{n}");
            let mut rid = None;
            if let Ok(values) = hive.list_values(&path) {
                for (vn, v) in &values {
                    if vn.is_empty() {
                        if let RegValue::Binary(b) = v {
                            rid = rid_from_names_blob(b, &known);
                        }
                    }
                }
            }
            let ft = hive
                .open(&path)
                .ok()
                .and_then(|node| nk_timestamp(hive_bytes, node.offset()))
                .or_else(|| rid_ft.iter().find(|(r, _)| Some(*r) == rid).and_then(|(_, f)| *f));
            out.push(AcctInfo {
                name: n,
                rid: rid.unwrap_or(0),
                key_ft: ft,
            });
        }
    }
    out
}

/// C:\Users 下不属于任何账户的系统/模板项
const SYSTEM_PROFILES: &[&str] = &["Public", "Default", "Default User", "All Users", "desktop.ini"];

/// IIS 应用程序池虚拟账户的配置目录特征（.NET v4.5 / DefaultAppPool 等，非 SAM 账户）
pub fn is_iis_pool_profile(name: &str) -> bool {
    name == "DefaultAppPool"
        || name == "Classic .NET AppPool"
        || name.starts_with(".NET")
        || name.starts_with("ASP.NET")
}

/// ProfileList（HKLM\...\CurrentVersion\ProfileList）登记的全部配置目录名。
/// 包含本地**和域**账户（SID→ProfileImagePath 基名），是"目录是否归属账户"的
/// 权威判定源——只对照本地 SAM 会在域机器上把每个域用户目录误报为孤儿。
pub fn profilelist_dir_names() -> Vec<String> {
    let root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    let Ok(sids) = crate::regutil::subkeys(crate::regutil::HKEY::local_machine(), root) else {
        return Vec::new();
    };
    sids.iter()
        .filter_map(|sid| {
            crate::regutil::read_string_value(
                crate::regutil::HKEY::local_machine(),
                &format!(r"{root}\{sid}"),
                "ProfileImagePath",
            )
            .ok()
            .map(|p| {
                crate::encoding::expand_env_vars(&p)
                    .rsplit('\\')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            })
            .filter(|s| !s.is_empty())
        })
        .collect()
}

/// 配置目录分类：(目录名, 分类)
/// 系统项 → "系统模板"；IIS 特征 → "IIS 应用池虚拟账户"；ProfileList 或本地账户
/// 命中 → "账户配置"；其余由调用方定孤儿
pub fn classify_profile_dir(
    name: &str,
    account_names: &[String],
    profilelist_dirs: &[String],
) -> &'static str {
    if SYSTEM_PROFILES.iter().any(|s| s.eq_ignore_ascii_case(name)) {
        return "系统模板";
    }
    if is_iis_pool_profile(name) {
        return "IIS 应用程序池（虚拟账户，不在 SAM）";
    }
    let lower = name.to_ascii_lowercase();
    if profilelist_dirs.iter().any(|p| *p == lower) {
        return "账户配置（含域账户）";
    }
    if account_names.iter().any(|a| a.eq_ignore_ascii_case(name)) {
        return "账户配置";
    }
    // ProfileList 与本地账户表均无记录：目录可能已被删除（或由服务/安装程序创建）
    "⚠ 无账户对应（可能已删除/服务创建）"
}

/// 目录创建时间（Windows 支持创建时间；失败回退修改时间）
fn dir_created(p: &std::path::Path) -> Option<String> {
    let m = std::fs::metadata(p).ok()?;
    let t = m.created().or_else(|_| m.modified()).ok()?;
    Some(
        chrono::DateTime::<chrono::Local>::from(t)
            .format("%Y-%m-%d %H:%M:%S.000")
            .to_string(),
    )
}

/// PowerShell Get-LocalUser 补充信息（普通权限可查）
#[derive(Debug)]
pub struct PsUser {
    pub name: String,
    pub enabled: Option<bool>,
    pub last_logon: String,
    pub password_last_set: String,
    pub rid: u32,
}

/// 解析 Get-LocalUser/Get-LocalGroupMember 合并 JSON 输出（纯函数便于测试）
pub fn parse_ps_users(json: &serde_json::Value) -> Vec<PsUser> {
    json.get("Users")
        .and_then(|u| u.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|o| {
                    let name = o.get("Name")?.as_str()?.to_string();
                    let sid = o.get("Sid").and_then(|s| s.as_str()).unwrap_or("");
                    let rid = sid
                        .rsplit('-')
                        .next()
                        .and_then(|r| r.parse().ok())
                        .unwrap_or(0);
                    Some(PsUser {
                        name,
                        enabled: o.get("Enabled").and_then(|e| e.as_bool()),
                        last_logon: o
                            .get("LastLogon")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string(),
                        password_last_set: o
                            .get("PasswordLastSet")
                            .and_then(|s| s.as_str())
                            .unwrap_or("")
                            .to_string(),
                        rid,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// (组名, 成员) 列表
pub fn parse_ps_groups(json: &serde_json::Value) -> Vec<(String, String)> {
    json.get("Groups")
        .and_then(|g| g.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|o| {
                    let grp = o.get("Group")?.as_str()?.to_string();
                    let member = o.get("Member")?.as_str()?.to_string();
                    Some((grp, member))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 账户所在组（成员名可带 MACHINE\ 前缀或为 SID）
pub fn groups_of(name: &str, groups: &[(String, String)]) -> Vec<String> {
    let l = name.to_lowercase();
    groups
        .iter()
        .filter(|(_, m)| {
            let ml = m.to_lowercase();
            ml == l || ml.ends_with(&format!("\\{l}"))
        })
        .map(|(g, _)| g.clone())
        .collect()
}

/// 一次 PowerShell 调用取用户状态 + 关键组（管理员组 / 远程桌面组）
pub fn query_user_info(logs: &mut Vec<String>) -> (Vec<PsUser>, Vec<(String, String)>) {
    // Win32 API 直调（NetUserEnum Level 1 + NetLocalGroupGetMembers）：
    // 零子进程；Level 1 无 LastLogon/PasswordLastSet——由 SAM 键时间补充
    match crate::winapi::enumerate_local_users() {
        Ok((users, groups)) => (users, groups),
        Err(e) => {
            logs.push(format!("用户状态查询失败（NetUserEnum）：{e}"));
            (Vec::new(), Vec::new())
        }
    }
}

pub struct AccountCollector;

impl Default for AccountCollector {
    fn default() -> Self {
        Self
    }
}

impl Collector for AccountCollector {
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

        // ---- SAM 解析（需管理员；隐藏/克隆检测的权威来源）----
        // 直读 → （已提权时）reg save 导出副本：SAM 文件常被系统独占锁住，
        // reg save 走备份语义（BackupPrivilege），提权下通常可用
        let mut accounts: Vec<AcctInfo> = match acquire_sam(&mut logs) {
            Some(bytes) => match Hive::from_bytes(bytes.clone()) {
                Ok(hive) => {
                    let a = collect_accounts(&hive, &bytes);
                    if a.is_empty() {
                        logs.push("SAM 中未枚举到用户账号（结构异常）".into());
                    }
                    a
                }
                Err(e) => {
                    logs.push(format!("SAM hive 解析失败：{e}"));
                    Vec::new()
                }
            },
            None => {
                logs.push(
                    "SAM 不可读（直读与 reg save 均失败）：隐藏/克隆账号检测需以管理员身份运行"
                        .into(),
                );
                Vec::new()
            }
        };

        // ---- PowerShell 补充：状态/组/最后登录（普通权限可查）----
        let (ps_users, groups) = query_user_info(&mut logs);
        // PS 独有账户（SAM 不可读时的兜底来源）并入清单
        for u in &ps_users {
            if !accounts
                .iter()
                .any(|a| a.name.eq_ignore_ascii_case(&u.name))
            {
                accounts.push(AcctInfo {
                    name: u.name.clone(),
                    rid: u.rid,
                    key_ft: None,
                });
            }
        }

        let mut flagged = 0usize;
        // ---- C:\Users 配置目录交叉核对（孤儿目录=账户可能被删，IIS 虚拟账户识别）----
        // ProfileList 覆盖本地+域账户：域机器上域用户目录不再误报为孤儿
        let account_names: Vec<String> = accounts.iter().map(|a| a.name.clone()).collect();
        let profilelist_dirs = profilelist_dir_names();
        let mut has_profile: Vec<String> = Vec::new();
        let mut orphans = 0usize;
        if let Ok(entries) = std::fs::read_dir(r"C:\Users") {
            for e in entries.filter_map(|e| e.ok()) {
                if !e.path().is_dir() {
                    continue;
                }
                let name = e.file_name().to_string_lossy().to_string();
                let class = classify_profile_dir(&name, &account_names, &profilelist_dirs);
                match class {
                    "账户配置" | "账户配置（含域账户）" => {
                        has_profile.push(name.to_ascii_lowercase())
                    }
                    "⚠ 无账户对应（可能已删除/服务创建）" => {
                        orphans += 1;
                        let t = dir_created(&e.path())
                            .unwrap_or_else(|| "（无时间戳）".into());
                        events.push(ActivityEvent {
                            time: t.clone(),
                            kind: "账号安全".into(),
                            desc: format!("无账户对应的配置目录：C:\\Users\\{name}"),
                            info: format!(
                                "ProfileList 与本地账户表均无记录——账户可能已被删除，或由服务/安装程序创建（应急关注）· 目录创建/修改时间 {t}"
                            ),
                            module: MODULE.into(),
                            sev: Sev::Yellow,
                            tags: vec![Tag {
                                sev: Sev::Yellow,
                                text: "R-015 孤儿配置目录".into(),
                            }],
                        });
                        rows.push(vec![
                            format!("（目录）{name}"),
                            "—".into(),
                            "—".into(),
                            String::new(),
                            "—".into(),
                            "—".into(),
                            t,
                            "无（孤儿目录）".into(),
                            class.to_string(),
                        ]);
                    }
                    _ => {} // 系统模板 / IIS 虚拟账户：记日志不进表
                }
            }
        }
        for a in &accounts {
            let ps = ps_users
                .iter()
                .find(|u| u.name.eq_ignore_ascii_case(&a.name));
            let notes = account_notes(&a.name, a.rid, &accounts);
            let suspicious = !notes.is_empty();
            if suspicious {
                flagged += 1;
            }
            let key_time = a
                .key_ft
                .and_then(filetime_to_local);
            let last_logon = ps.map(|u| u.last_logon.clone()).unwrap_or_default();
            let enable_txt = match ps.and_then(|u| u.enabled) {
                Some(true) => "启用",
                Some(false) => "禁用",
                None => "",
            };
            let grp_txt = groups_of(&a.name, &groups).join("、");
            let rid = if a.rid > 0 {
                a.rid.to_string()
            } else {
                "未知".into()
            };
            let profile_txt = if has_profile.contains(&a.name.to_ascii_lowercase()) {
                "✓".to_string()
            } else {
                "—（未建立配置）".to_string()
            };

            // 时间优先级：SAM 键最后写入 > PS 最后登录（如实标注来源）
            let (time, time_src) = match (&key_time, &last_logon) {
                (Some(t), _) => (t.clone(), "键最后写入"),
                (None, l) if !l.is_empty() => (format!("{l}.000"), "最后登录时间"),
                _ => ("（无时间戳）".into(), ""),
            };
            let tag = if suspicious {
                vec![Tag {
                    sev: Sev::Red,
                    text: "R-013 隐藏/克隆账号".into(),
                }]
            } else {
                vec![]
            };
            events.push(ActivityEvent {
                time: time.clone(),
                kind: "账号安全".into(),
                desc: format!("本地账户 {}（RID {rid}）", a.name),
                info: {
                    let mut parts = Vec::new();
                    if !enable_txt.is_empty() {
                        parts.push(enable_txt.to_string());
                    }
                    if !grp_txt.is_empty() {
                        parts.push(grp_txt.clone());
                    }
                    if !last_logon.is_empty() {
                        parts.push(format!("最后登录 {last_logon}"));
                    }
                    if !notes.is_empty() {
                        parts.insert(0, format!("⚠ {}", notes.join("；")));
                    }
                    parts.push(format!("{time_src}（≈创建/最后修改）"));
                    parts.join(" · ")
                },
                module: MODULE.into(),
                sev: if suspicious { Sev::Red } else { Sev::None },
                tags: tag,
            });
            rows.push(vec![
                a.name.clone(),
                rid,
                enable_txt.into(),
                grp_txt,
                if last_logon.is_empty() { "—".into() } else { last_logon.clone() },
                ps.map(|u| u.password_last_set.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "—".into()),
                key_time.unwrap_or_else(|| "—".into()),
                profile_txt,
                if notes.is_empty() {
                    String::new()
                } else {
                    format!("⚠ {}", notes.join("；"))
                },
            ]);
        }
        logs.push(format!(
            "共 {} 个本地账号（PowerShell 补充状态/组信息 {} 个），检出可疑 {} 个；配置目录交叉核对：孤儿目录 {} 个（IIS 应用池/系统模板目录已识别排除）",
            accounts.len(),
            ps_users.len(),
            flagged,
            orphans
        ));
        ModuleResult {
            module: self.id().into(),
            status: if accounts.is_empty() {
                ModuleStatus::Warn
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
                columns: [
                    "账户",
                    "RID",
                    "状态",
                    "所在组",
                    "最后登录",
                    "密码最后设置",
                    "键最后写入（≈创建/修改）",
                    "配置目录",
                    "备注",
                ]
                .iter()
                .map(|s| s.to_string())
                .collect(),
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
    fn rid_blob_matches_known_rid() {
        let known = [500u32, 1000, 1001];
        // RID 1000 = 0xE8030000 在偏移 4
        let blob = vec![0x30, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00];
        assert_eq!(rid_from_names_blob(&blob, &known), Some(1000));
    }

    #[test]
    fn rid_blob_ignores_zero_and_unknown() {
        assert_eq!(rid_from_names_blob(&[0; 8], &[500]), None);
        assert_eq!(rid_from_names_blob(&[0x99; 8], &[500]), None);
        assert_eq!(rid_from_names_blob(&[0xef; 4], &[500]), None);
    }

    #[test]
    fn detects_hidden_and_clone() {
        let accts = vec![
            AcctInfo { name: "Administrator".into(), rid: 500, key_ft: None },
            AcctInfo { name: "hack$".into(), rid: 1010, key_ft: None },
            AcctInfo { name: "helpdesk".into(), rid: 500, key_ft: None },
        ];
        assert!(account_notes("hack$", 1010, &accts).len() == 1);
        let n = account_notes("helpdesk", 500, &accts);
        assert!(n.iter().any(|x| x.contains("克隆管理员")));
        assert!(n.iter().any(|x| x.contains("共享同一 RID")));
        // Administrator 与克隆者共享 RID 也会被标出共享（仅此一条，无隐藏/RID500 误报）
        let admin = account_notes("Administrator", 500, &accts);
        assert_eq!(admin.len(), 1);
        assert!(admin[0].contains("共享同一 RID"));
        // 无克隆时 Administrator 干净
        let clean = vec![AcctInfo { name: "Administrator".into(), rid: 500, key_ft: None }];
        assert!(account_notes("Administrator", 500, &clean).is_empty());
    }

    #[test]
    fn synthetic_sam_hive_roundtrip() {
        // 构造 SAM\Domains\Account\Users(000001F4/000003E8/000003F2) + Names 结构
        let mut h = Hive::new_empty("SAM");
        let base = r"SAM\Domains\Account";
        for (rk, _n) in [("000001F4", 500u32), ("000003E8", 1000), ("000003F2", 1010)] {
            h.create_key(&format!(r"{base}\Users\{rk}")).unwrap();
        }
        let names = [
            ("Administrator", 500u32),
            ("alice", 1000),
            ("hack$", 1010),
        ];
        for (n, rid) in names {
            // 真实结构：Names 与 Users 同级（SAM\Domains\Account\Names）
            let p = format!(r"{base}\Names\{n}");
            h.create_key(&p).unwrap();
            h.set_value(
                &p,
                "",
                RegValue::Binary(vec![0x30, 0, 0, 0, rid.to_le_bytes()[0], rid.to_le_bytes()[1], 0, 0]),
            )
            .unwrap();
        }
        let bytes = h.to_bytes();

        // 盖时间戳：alice 用户 RID 键
        let probe = Hive::from_bytes(bytes.clone()).unwrap();
        let node = probe.open(&format!(r"{base}\Users\000003E8")).unwrap();
        let abs = REGF_BASE_BLOCK + node.offset() as usize + 8;
        let mut stamped = bytes;
        let ft: u64 = 134_345_473_332_450_000;
        stamped[abs..abs + 8].copy_from_slice(&ft.to_le_bytes());

        let hive = Hive::from_bytes(stamped.clone()).unwrap();
        let accts = collect_accounts(&hive, &stamped);
        assert_eq!(accts.len(), 3, "{:?}", accts);
        let hua = accts.iter().find(|a| a.name == "alice").unwrap();
        assert_eq!(hua.rid, 1000);
        assert!(hua.key_ft.is_some());
        let hack = accts.iter().find(|a| a.name == "hack$").unwrap();
        assert_eq!(hack.rid, 1010);
        assert_eq!(account_notes("hack$", 1010, &accts).len(), 1);
    }

    #[test]
    fn ps_users_parsed_with_rid() {
        let j: serde_json::Value = serde_json::from_str(
            r#"{"Users":[{"Name":"alice","Enabled":true,"Sid":"S-1-5-21-1-2-1001","LastLogon":"2026-09-25 09:00:00","PasswordLastSet":"2026-01-01 00:00:00"},
{"Name":"Guest","Enabled":false,"Sid":"S-1-5-21-1-2-501","LastLogon":"","PasswordLastSet":""}],
"Groups":[{"Group":"Administrators","Member":"PC\\alice"}]}"#,
        )
        .unwrap();
        let users = parse_ps_users(&j);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].rid, 1001);
        assert_eq!(users[0].enabled, Some(true));
        let groups = parse_ps_groups(&j);
        assert_eq!(groups, vec![("Administrators".to_string(), "PC\\alice".to_string())]);
        assert_eq!(groups_of("alice", &groups), vec!["Administrators"]);
        assert!(groups_of("guest", &groups).is_empty());
    }

    #[test]
    fn profile_dir_classification() {
        let accts = vec!["alice".to_string(), "spider2".to_string()];
        // 域账户：不在本地账户表、但 ProfileList 有登记 → 不再误报为孤儿
        let pl = vec!["domain.user".to_string(), "corp\\admin".to_lowercase()];
        assert_eq!(classify_profile_dir("alice", &accts, &pl), "账户配置");
        assert_eq!(classify_profile_dir("domain.user", &accts, &pl), "账户配置（含域账户）");
        assert_eq!(classify_profile_dir("public", &accts, &pl), "系统模板");
        assert_eq!(classify_profile_dir("Default User", &accts, &pl), "系统模板");
        assert_eq!(
            classify_profile_dir(".NET v4.5", &accts, &pl),
            "IIS 应用程序池（虚拟账户，不在 SAM）"
        );
        assert_eq!(
            classify_profile_dir("DefaultAppPool", &accts, &pl),
            "IIS 应用程序池（虚拟账户，不在 SAM）"
        );
        // ProfileList 与本地账户表均无 → 孤儿（spider 不在任何清单里）
        assert!(classify_profile_dir("spider", &accts, &pl).contains("无账户对应"));
        // 空 ProfileList 时本地账户仍生效（旧路径回归）
        assert_eq!(classify_profile_dir("alice", &accts, &vec![]), "账户配置");
        assert!(classify_profile_dir("spider", &accts, &vec![]).contains("无账户对应"));
    }

    #[test]
    #[ignore = "真实 PowerShell；本机 cargo test -- --ignored"]
    fn real_users_enriched() {
        let r = AccountCollector::default().run();
        // 非提权也能拿到 PowerShell 部分（本机至少 3 个内置账户）
        assert!(r.count >= 3, "{:?}", r.logs);
        let raw = r.raw.as_ref().unwrap();
        // 9 列：账户/RID/状态/所在组/最后登录/密码最后设置/键最后写入/配置目录/备注
        assert_eq!(raw.columns.len(), 9);
        assert!(raw.rows.iter().any(|row| row[2] == "启用"));
    }

    #[test]
    fn collector_degrades_without_admin() {
        let r = AccountCollector::default().run();
        assert!(!r.logs.is_empty());
        matches!(r.status, ModuleStatus::Ok | ModuleStatus::Warn);
    }
}
