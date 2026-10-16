//! Win32 API 直调：替代外部命令（PowerShell/wevtutil 等），消灭子进程行为。
//! 数据源与 PowerShell cmdlet 完全一致（cmdlet 本身就是这些 API 的薄封装），
//! 取证权威性零影响。
//!
//! 1a. 进程枚举：CreateToolhelp32Snapshot + Process32First/Next 遍历，
//!     NtQueryInformationProcess(ProcessCommandLineInformation) 读命令行，
//!     QueryFullProcessImageNameW 读路径，GetProcessTimes 读创建时间。

use crate::modules::live_proc::ProcInfo;

extern "system" {
    fn NtQueryInformationProcess(
        process_handle: isize,
        process_information_class: u32,
        process_information: *mut core::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// 信息类编号
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

/// 枚举当前全部进程：PID/PPID/名称/路径/命令行/创建时间。
/// 等价于 `Get-CimInstance Win32_Process`，但不启动任何子进程。
pub fn enumerate_processes() -> Result<Vec<ProcInfo>, String> {
    unsafe { snapshot_processes() }
}

unsafe fn snapshot_processes() -> Result<Vec<ProcInfo>, String> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == 0 {
        return Err("CreateToolhelp32Snapshot 失败".into());
    }

    let mut out = Vec::new();
    let mut pe: PROCESSENTRY32W = std::mem::zeroed();
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(snap, &mut pe) != 0 {
        loop {
            let name = widestr_to_string(pe.szExeFile.as_ptr());
            let pid = pe.th32ProcessID;
            let ppid = pe.th32ParentProcessID;
            let (path, cmd, created) = get_process_detail(pid);

            out.push(ProcInfo { pid, ppid, name, path, cmd, created });

            if Process32NextW(snap, &mut pe) == 0 {
                break;
            }
        }
    }

    windows_sys::Win32::Foundation::CloseHandle(snap);
    Ok(out)
}

/// 打开目标进程，读完整路径 + 命令行 + 创建时间。
/// 两级策略：LIMITED（覆盖面广）读路径/时间 → FULL（覆盖面窄）追加命令行。
/// 非提权：LIMITED 能打开用户进程（路径/时间可用），FULL 只能打开自身
/// → 命令行仅在可打开时读到（提权后全覆盖）。
unsafe fn get_process_detail(pid: u32) -> (String, String, String) {
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // 第一级：LIMITED 权限——读路径和创建时间（覆盖面最广）
    let h_lim = OpenProcess(0x1000, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
    let (path, created) = if h_lim != 0 {
        let p = query_full_path(h_lim);
        let c = query_creation_time(h_lim);
        windows_sys::Win32::Foundation::CloseHandle(h_lim);
        (p, c)
    } else {
        (String::new(), String::new())
    };

    // 第二级：FULL 权限 + VM_READ——读命令行（需要 NtQueryInformationProcess）
    let h_full = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    let cmd = if h_full != 0 {
        let c = read_command_line_via_nt(h_full);
        windows_sys::Win32::Foundation::CloseHandle(h_full);
        c
    } else {
        String::new()
    };

    (path, cmd, created)
}

/// QueryFullProcessImageNameW 获取完整可执行文件路径
unsafe fn query_full_path(h: isize) -> String {
    use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    if QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0 && len > 0 {
        String::from_utf16_lossy(&buf[..len as usize])
    } else {
        String::new()
    }
}

/// NtQueryInformationProcess(ProcessCommandLineInformation) 读命令行。
/// 返回 UNICODE_STRING{Length, MaxLength, pad, Buffer}，Buffer 指向目标进程
/// 自身地址空间——再用 ReadProcessMemory 读出字符串内容。
/// 比 PEB 链路更可靠（不受 PEB 布局版本差异影响）。
unsafe fn read_command_line_via_nt(h: isize) -> String {
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    let mut buf = vec![0u8; 8192];
    let mut ret_len: u32 = 0;
    let status = NtQueryInformationProcess(
        h,
        PROCESS_COMMAND_LINE_INFORMATION,
        buf.as_mut_ptr() as *mut core::ffi::c_void,
        buf.len() as u32,
        &mut ret_len,
    );
    if status != 0 || ret_len < 16 {
        return String::new();
    }

    // UNICODE_STRING 布局：+0 Length(u16) +2 MaxLength(u16) +4 pad(u32) +8 Buffer(u64)
    let length = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    let buf_addr = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    if length == 0 || buf_addr == 0 || length > 32768 || length % 2 != 0 {
        return String::new();
    }

    let n = (length / 2).min(16384);
    let mut wbuf = vec![0u16; n];
    if ReadProcessMemory(
        h,
        buf_addr as *const core::ffi::c_void,
        wbuf.as_mut_ptr() as *mut core::ffi::c_void,
        length,
        std::ptr::null_mut(),
    ) == 0
    {
        return String::new();
    }

    String::from_utf16_lossy(&wbuf)
}

/// GetProcessTimes 获取创建时间（转 "yyyy-MM-dd HH:mm:ss" 本地格式）
unsafe fn query_creation_time(h: isize) -> String {
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    use windows_sys::Win32::Foundation::FILETIME;

    let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut _exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut _kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let mut _user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };

    if GetProcessTimes(h, &mut creation, &mut _exit, &mut _kernel, &mut _user) == 0 {
        return String::new();
    }

    let ft = (creation.dwHighDateTime as u64) << 32 | creation.dwLowDateTime as u64;
    if ft == 0 {
        return String::new();
    }
    filetime_to_local_string(ft)
}

/// FILETIME (100ns since 1601) → "yyyy-MM-dd HH:mm:ss" 本地时间
fn filetime_to_local_string(ft: u64) -> String {
    let unix_ms = (ft / 10_000) as i64 - 11_644_473_600_000;
    use chrono::TimeZone;
    chrono::Local
        .timestamp_millis_opt(unix_ms)
        .single()
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_default()
}

/// 宽字符数组（NUL 结尾）→ String
unsafe fn widestr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 && len < 260 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_current_processes() {
        let procs = enumerate_processes().expect("进程枚举应成功");
        assert!(procs.len() >= 50, "至少应有 50 个进程：{}", procs.len());
        let cur = std::process::id();
        assert!(procs.iter().any(|p| p.pid == cur), "自身 PID {cur} 应在列表中");
        assert!(procs.iter().any(|p| p.pid == 0));
        assert!(procs.iter().any(|p| p.pid == 4));
    }

    #[test]
    fn current_process_has_path_and_cmdline() {
        let procs = enumerate_processes().expect("进程枚举应成功");
        let cur = std::process::id();
        let me = procs.iter().find(|p| p.pid == cur).expect("自身应在列表中");
        assert!(!me.path.is_empty(), "自身进程应有路径");
        assert!(!me.cmd.is_empty(), "自身进程应有命令行");
        assert!(!me.created.is_empty(), "自身进程应有创建时间");
        assert!(me.path.ends_with(".exe"), "路径应以 .exe 结尾：{}", me.path);
    }

    #[test]
    fn accessible_processes_have_details() {
        let procs = enumerate_processes().expect("进程枚举应成功");
        let with_path = procs.iter().filter(|p| !p.path.is_empty()).count();
        let with_cmd = procs.iter().filter(|p| !p.cmd.is_empty()).count();
        // 非提权环境下能打开自身用户的进程（约 30-50%），
        // 提权后几乎全部可读
        assert!(
            with_path as f64 / procs.len() as f64 > 0.15,
            "有路径的进程比例过低：{with_path}/{}",
            procs.len()
        );
        // 非提权 cargo test 只能读自身用户的进程（命令行只有自身 1 个）
        // 提权后全覆盖。>0 保证至少自身进程命令行读到了
        assert!(with_cmd >= 1, "至少自身进程应有命令行：{with_cmd}");
    }

    #[test]
    fn system_process_ppid_is_idle() {
        let procs = enumerate_processes().expect("进程枚举应成功");
        let system = procs.iter().find(|p| p.pid == 4).unwrap();
        assert!(system.ppid == 0, "System(4) 的 PPID 应为 0（Idle），实际 {}", system.ppid);
    }
}

// ---- 1b. TCP/UDP 连接表（替代 powershell Get-NetTCPConnection / Get-NetUDPEndpoint）----

use crate::modules::live_net::ConnInfo;

/// 枚举当前 TCP + UDP 连接。等价于 Get-NetTCPConnection + Get-NetUDPEndpoint。
pub fn enumerate_connections() -> Result<Vec<ConnInfo>, String> {
    let mut out = Vec::new();
    out.extend(tcp_table()?);
    out.extend(udp_table()?);
    Ok(out)
}

fn tcp_table() -> Result<Vec<ConnInfo>, String> {
    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable;
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        // TCP_TABLE_OWNER_MODULE_ALL = 5
        const TABLE_CLASS: i32 = 5;
        let mut size: u32 = 0;
        // 第一次调用获取所需大小
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0, // TCP_TABLE_OWNER_MODULE_ALL
            AF_INET as u32,
            TABLE_CLASS,
            0,
        );
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET as u32,
            TABLE_CLASS,
            0,
        );
        if ret != 0 {
            return Err(format!("GetExtendedTcpTable 失败：{ret}"));
        }

        // MIB_TCPTABLE_OWNER_MODULE 布局：
        //   +0  dwNumEntries (u32)
        //   +4  table[] — MIB_TCPROW_OWNER_MODULE:
        //     +0  dwState (u32)
        //     +4  dwLocalAddr (u32, 网络字节序)
        //     +8  dwLocalPort (u32, 网络字节序高 16 位有效)
        //     +12 dwRemoteAddr (u32)
        //     +16 dwRemotePort (u32)
        //     +20 dwOwningPid (u32)
        //     +24 liCreateTimestamp (i64)
        //     +32 OwningModuleInfo[16] (u64 × 16)
        //   行大小 = 32 + 128 = 160 字节

        let num = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = 160usize;
        let mut out = Vec::with_capacity(num);

        for i in 0..num {
            let off = 4 + i * row_size;
            if off + row_size > buf.len() { break; }
            let state = u32::from_le_bytes(buf[off..off+4].try_into().unwrap());
            let local_addr = u32::from_le_bytes(buf[off+4..off+8].try_into().unwrap());
            let local_port_raw = u32::from_le_bytes(buf[off+8..off+12].try_into().unwrap());
            let remote_addr = u32::from_le_bytes(buf[off+12..off+16].try_into().unwrap());
            let remote_port_raw = u32::from_le_bytes(buf[off+16..off+20].try_into().unwrap());
            let pid = u32::from_le_bytes(buf[off+20..off+24].try_into().unwrap());

            let local = format!("{}:{}", ipv4_to_string(local_addr), port_from_raw(local_port_raw));
            let remote = format!("{}:{}", ipv4_to_string(remote_addr), port_from_raw(remote_port_raw));
            let state_str = tcp_state_name(state);

            out.push(ConnInfo {
                proto: "TCP".into(),
                local,
                remote,
                state: state_str.into(),
                pid,
            });
        }
        Ok(out)
    }
}

fn udp_table() -> Result<Vec<ConnInfo>, String> {
    unsafe {
        use windows_sys::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable;
        use windows_sys::Win32::Networking::WinSock::AF_INET;

        const TABLE_CLASS: i32 = 2; // UDP_TABLE_OWNER_MODULE
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TABLE_CLASS,
            0,
        );
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            0,
            AF_INET as u32,
            TABLE_CLASS,
            0,
        );
        if ret != 0 {
            return Err(format!("GetExtendedUdpTable 失败：{ret}"));
        }

        // MIB_UDPTABLE_OWNER_MODULE:
        //   +0 dwNumEntries (u32)
        //   +4 table[] — MIB_UDPROW_OWNER_MODULE:
        //     +0  dwLocalAddr (u32)
        //     +4  dwLocalPort (u32)
        //     +8  dwOwningPid (u32)
        //     +12 liCreateTimestamp (i64)
        //     +20 OwningModuleInfo[16] (u64 × 16)
        //   行大小 = 24 + 128 = 152 字节

        let num = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = 152usize;
        let mut out = Vec::with_capacity(num);

        for i in 0..num {
            let off = 4 + i * row_size;
            if off + row_size > buf.len() { break; }
            let local_addr = u32::from_le_bytes(buf[off..off+4].try_into().unwrap());
            let local_port_raw = u32::from_le_bytes(buf[off+4..off+8].try_into().unwrap());
            let pid = u32::from_le_bytes(buf[off+8..off+12].try_into().unwrap());

            let local = format!("{}:{}", ipv4_to_string(local_addr), port_from_raw(local_port_raw));
            out.push(ConnInfo {
                proto: "UDP".into(),
                local,
                remote: String::new(),
                state: String::new(),
                pid,
            });
        }
        Ok(out)
    }
}

/// 网络字节序 u32 → "a.b.c.d"
fn ipv4_to_string(addr: u32) -> String {
    // 网络字节序（大端）：高位字节在前
    format!("{}.{}.{}.{}", (addr >> 24) & 0xff, (addr >> 16) & 0xff, (addr >> 8) & 0xff, addr & 0xff)
}

/// dwPort 原始值：高 16 位是端口号（网络字节序）
fn port_from_raw(raw: u32) -> u16 {
    ((raw >> 8) & 0xff | ((raw & 0xff) << 8)) as u16
}

fn tcp_state_name(state: u32) -> &'static str {
    match state {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod conn_tests {
    use super::*;

    #[test]
    fn tcp_connections_present() {
        let conns = enumerate_connections().expect("连接枚举应成功");
        let tcp = conns.iter().filter(|c| c.proto == "TCP").count();
        assert!(tcp > 5, "至少 5 条 TCP 连接：{tcp}");
        let listen = conns.iter().filter(|c| c.state == "LISTEN").count();
        assert!(listen > 0, "至少 1 条 LISTEN");
    }

    #[test]
    fn udp_endpoints_present() {
        let conns = enumerate_connections().expect("连接枚举应成功");
        let udp = conns.iter().filter(|c| c.proto == "UDP").count();
        assert!(udp > 0, "至少 1 条 UDP：{udp}");
    }

    #[test]
    fn established_connections_have_remote() {
        let conns = enumerate_connections().expect("连接枚举应成功");
        let est = conns.iter().filter(|c| c.state == "ESTABLISHED");
        let mut checked = 0;
        for c in est {
            assert!(c.remote.contains(':'), "ESTABLISHED 应有远程地址：{}", c.remote);
            assert!(c.pid > 0, "ESTABLISHED 应有 PID");
            checked += 1;
            if checked >= 5 { break; }
        }
        assert!(checked > 0, "至少 1 条 ESTABLISHED");
    }

    #[test]
    fn port_and_ip_format_valid() {
        let conns = enumerate_connections().expect("连接枚举应成功");
        for c in conns.iter().take(10) {
            // 本地地址应为 "x.x.x.x:port" 格式
            assert!(c.local.contains('.') && c.local.contains(':'),
                "地址格式：{}", c.local);
        }
    }
}

// ---- 1c. DNS 缓存计数（替代 powershell Get-DnsClientCache）----

/// 获取 DNS 缓存条目数。等价于 @(Get-DnsClientCache).Count。
pub fn dns_cache_count() -> usize {
    unsafe {
        #[repr(C)]
        struct DnsCacheEntry {
            next: *mut DnsCacheEntry,   // 链表指针
            _psz_name: *const u16,      // 域名
            _w_type: u16,
            _w_data_length: u16,
            _dw_flags: u32,
        }
        #[link(name = "dnsapi")]
        extern "system" {
            fn DnsGetCacheDataTable(pp_entry: *mut *mut DnsCacheEntry) -> i32;
            fn DnsFree(p_data: *mut core::ffi::c_void, free_type: u32);
        }
        let mut head: *mut DnsCacheEntry = std::ptr::null_mut();
        if DnsGetCacheDataTable(&mut head) == 0 {
            return 0;
        }
        let mut count = 0usize;
        let mut cur = head;
        while !cur.is_null() {
            count += 1;
            cur = (*cur).next;
        }
        // 释放链表（DNS_FREE_TYPE = 1 = DnsFreeFlat）
        DnsFree(head as *mut _, 1);
        count
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn dns_cache_has_entries() {
        let n = dns_cache_count();
        // 正常系统至少有几条缓存（localhost 等）
        assert!(n > 0, "DNS 缓存应非空：{n}");
    }
}

// ---- 1d. 本地用户/组（替代 powershell Get-LocalUser / Get-LocalGroupMember）----

use crate::modules::account::{PsUser};

/// 枚举本地用户 + Administrators/Remote Desktop Users 组成员。
/// 等价于 Get-LocalUser + Get-LocalGroupMember，零子进程。
pub fn enumerate_local_users() -> Result<(Vec<PsUser>, Vec<(String, String)>), String> {
    let users = net_user_enum()?;
    let groups = local_group_members()?;
    Ok((users, groups))
}

/// NetUserEnum Level 1 枚举本地账户（名称/启用状态）
/// Level 23（含 SID）在部分系统不支持（ERROR_INVALID_LEVEL 124），Level 1 最稳。
/// RID 由 SAM 解析路径补充。
fn net_user_enum() -> Result<Vec<PsUser>, String> {
    unsafe {
        #[link(name = "netapi32")]
        extern "system" {
            fn NetUserEnum(
                servername: *const u16,
                level: u32,
                filter: u32,
                bufptr: *mut *mut u8,
                prefmaxlen: u32,
                entriesread: *mut u32,
                totalentries: *mut u32,
                resume_handle: *mut u32,
            ) -> u32;
            fn NetApiBufferFree(buffer: *mut core::ffi::c_void) -> u32;
        }

        // USER_INFO_1 布局（x64，实测 sizeof = 56）：
        // +0  usri1_name (LPWSTR, 8B)
        // +8  usri1_password (LPWSTR, 8B) — 始终为 NULL
        // +16 usri1_password_age (DWORD, 4B)
        // +20 usri1_priv (DWORD, 4B)
        // +24 usri1_home_dir (LPWSTR, 8B)
        // +32 usri1_comment (LPWSTR, 8B)
        // +40 usri1_flags (DWORD, 4B)
        // +44 pad (4B)
        // +48 usri1_script_path (LPWSTR, 8B)
        // 行大小 = 56 字节
        const LEVEL: u32 = 1;
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = NetUserEnum(
            std::ptr::null(),
            LEVEL,
            0,
            &mut buf,
            0xFFFFFFFF,
            &mut entries_read,
            &mut total_entries,
            std::ptr::null_mut(),
        );
        if status != 0 && status != 234 {
            return Err(format!("NetUserEnum 失败：{status}"));
        }
        if buf.is_null() || entries_read == 0 {
            return Ok(Vec::new());
        }

        let row_size = 56usize;
        let mut out = Vec::with_capacity(entries_read as usize);
        for i in 0..entries_read as usize {
            let base = buf.add(i * row_size);
            let name_ptr = std::ptr::read_unaligned(base as *const *const u16);
            let flags = std::ptr::read_unaligned(base.add(40) as *const u32);

            let name = if !name_ptr.is_null() {
                widestr_to_string(name_ptr)
            } else {
                String::new()
            };

            // UF_ACCOUNTDISABLE = 0x0002；enabled = !(flags & 2)
            let enabled = flags & 0x0002 == 0;

            // Level 1 无 SID / LastLogon / PasswordLastSet——由 SAM 路径补充
            out.push(PsUser {
                name,
                enabled: Some(enabled),
                last_logon: String::new(),
                password_last_set: String::new(),
                rid: 0,
            });
        }
        NetApiBufferFree(buf as _);
        Ok(out)
    }
}

/// 枚举 Administrators / Remote Desktop Users 组成员
fn local_group_members() -> Result<Vec<(String, String)>, String> {
    unsafe {
        #[link(name = "netapi32")]
        extern "system" {
            fn NetLocalGroupGetMembers(
                servername: *const u16,
                groupname: *const u16,
                level: u32,
                bufptr: *mut *mut u8,
                prefmaxlen: u32,
                entriesread: *mut u32,
                totalentries: *mut u32,
                resume_handle: *mut u32,
            ) -> u32;
            fn NetApiBufferFree(buffer: *mut core::ffi::c_void) -> u32;
        }

        let mut out = Vec::new();
        for group in ["Administrators", "Remote Desktop Users"] {
            let group_w: Vec<u16> = group.encode_utf16().chain(std::iter::once(0)).collect();

            // LOCALGROUP_MEMBERS_INFO_3（含域名\账户名）：
            // +0 lgrmi3_domainandname (LPWSTR)
            // 行大小 = 8 字节
            let mut buf: *mut u8 = std::ptr::null_mut();
            let mut read: u32 = 0;
            let mut total: u32 = 0;
            let status = NetLocalGroupGetMembers(
                std::ptr::null(),
                group_w.as_ptr(),
                3,
                &mut buf,
                0xFFFFFFFF,
                &mut read,
                &mut total,
                std::ptr::null_mut(),
            );
            if status != 0 && status != 234 {
                continue; // 组不存在或权限不足，跳过
            }
            if buf.is_null() { continue; }

            let row_size = 8usize;
            for i in 0..read as usize {
                let name_ptr = *(buf.add(i * row_size) as *const *const u16);
                let member = if !name_ptr.is_null() {
                    widestr_to_string(name_ptr)
                } else {
                    String::new()
                };
                out.push((group.to_string(), member));
            }
            NetApiBufferFree(buf as _);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod user_tests {
    use super::*;

    #[test]
    fn local_users_enumerated() {
        let (users, _) = enumerate_local_users().expect("用户枚举应成功");
        assert!(users.len() >= 2, "至少 Administrator + Guest：{users:?}");
        assert!(users.iter().any(|u| u.name.eq_ignore_ascii_case("Administrator")));
        // RID 从 SID 提取
        // RID 由 SAM 解析路径补充（Level 1 不含 SID）
    }

    #[test]
    fn admin_group_has_members() {
        let (_, groups) = enumerate_local_users().expect("组枚举应成功");
        let admins: Vec<_> = groups.iter().filter(|(g, _)| g == "Administrators").collect();
        assert!(!admins.is_empty(), "Administrators 组应有成员");
    }
}

// ---- 2a. 事件日志导出（替代 wevtutil epl）----

/// EvtExportLog 导出事件日志通道到 .evtx 文件（替代 `wevtutil epl`）。
/// channel: 如 "Security"；query: XPath 过滤（如 "*[System[(EventID=4688)]]"）；可省略。
pub fn export_event_log(channel: &str, query: Option<&str>, target_path: &str) -> Result<(), String> {
    unsafe {
        #[link(name = "wevtapi")]
        extern "system" {
            fn EvtExportLog(
                session: isize,             // NULL for local
                channel_path: *const u16,
                query: *const u16,
                target_file_path: *const u16,
                flags: u32,
            ) -> u32;
        }

        let channel_w: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();
        let query_buf: Vec<u16> = match query {
            Some(q) => q.encode_utf16().chain(std::iter::once(0)).collect(),
            None => Vec::new(),
        };
        // query 为 None 时必须传真正的 NULL 指针（= 全部事件）；空字符串 L"" 是非法查询
        let query_ptr = if query.is_some() {
            query_buf.as_ptr()
        } else {
            std::ptr::null()
        };
        let target_w: Vec<u16> = target_path.encode_utf16().chain(std::iter::once(0)).collect();

        // 目标文件已存在时导出会失败——先删（老系统无 Overwrite 标志，删文件最稳）
        let _ = std::fs::remove_file(target_path);

        // EvtExportLogChannelPath = 0x1（winevt.h）：Path 为通道名时必传，
        // flags=0 是非法组合 → Win32 错误 87。MSDN 散文档只提 FilePath=2，勿被误导。
        const EVT_EXPORT_LOG_CHANNEL_PATH: u32 = 0x1;
        let ret = EvtExportLog(
            0,
            channel_w.as_ptr(),
            query_ptr,
            target_w.as_ptr(),
            EVT_EXPORT_LOG_CHANNEL_PATH,
        );
        if ret == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(format!("EvtExportLog 失败（Win32 错误 {err}）"));
        }
        Ok(())
    }
}

// ---- 3a. 注册表 hive 备份（替代 reg save）----

/// RegSaveKeyEx 导出注册表键及其子键到 .hiv 文件（替代 `reg save`）。
/// 需要管理员权限 + SeBackupPrivilege。
pub fn save_registry_key(root: &str, subkey: &str, target_path: &str) -> Result<(), String> {
    unsafe {
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegSaveKeyExW, HKEY_LOCAL_MACHINE,
            KEY_READ, REG_STANDARD_FORMAT,
        };
        use windows_sys::Win32::Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
            SE_PRIVILEGE_ENABLED,
        };
        use windows_sys::Win32::Foundation::LUID;
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, OpenProcessToken,
        };

        // Step 1: 启用 SeBackupPrivilege（reg save 的隐藏前提）
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        let priv_name: Vec<u16> = "SeBackupPrivilege\0".encode_utf16().collect();
        if LookupPrivilegeValueW(std::ptr::null(), priv_name.as_ptr(), &mut luid) == 0 {
            return Err("LookupPrivilegeValueW(SeBackupPrivilege) 失败".into());
        }

        #[repr(C)]
        struct TokPriv {
            count: u32,
            luid: LUID,
            attr: u32,
        }
        let tp = TokPriv { count: 1, luid, attr: SE_PRIVILEGE_ENABLED };

        let mut token: isize = 0;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return Err("OpenProcessToken 失败".into());
        }
        let _ = AdjustTokenPrivileges(token as _, 0, &tp as *const _ as *const _,
            std::mem::size_of::<TokPriv>() as u32, std::ptr::null_mut(), std::ptr::null_mut());
        windows_sys::Win32::Foundation::CloseHandle(token as _);

        // Step 2: 打开注册表键
        let root_hkey = if root.eq_ignore_ascii_case("HKLM") || root.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE") {
            HKEY_LOCAL_MACHINE
        } else {
            return Err(format!("不支持的根：{root}（目前仅 HKLM）"));
        };
        let subkey_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let mut hkey: isize = 0;
        if RegOpenKeyExW(root_hkey, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return Err(format!("RegOpenKeyExW {root}{}{subkey} 失败", "\\"));
        }

        // Step 3: RegSaveKeyExW 导出到文件
        let target_w: Vec<u16> = target_path.encode_utf16().chain(std::iter::once(0)).collect();
        let ret = RegSaveKeyExW(hkey as _, target_w.as_ptr(), std::ptr::null(), REG_STANDARD_FORMAT);
        RegCloseKey(hkey as _);
        if ret != 0 {
            return Err(format!("RegSaveKeyExW 失败：{ret}"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod export_tests {
    use super::*;

    #[test]
    fn export_system_log() {
        let tmp = std::env::temp_dir().join("lmss-test-export.evtx");
        let _ = std::fs::remove_file(&tmp);
        let r = export_event_log("System", Some("*[System[(EventID=6005)]]"), tmp.to_str().unwrap());
        if let Err(e) = &r {
            // 仅权限类失败可容忍（加固环境下 System 通道也可能拒绝导出）；
            // 参数错误（如 flags=0 → 错误 87）必须当失败暴露
            assert!(
                e.contains("错误 5") || e.contains("错误 1810"),
                "System 通道导出应成功（wevtutil 同权可用）：{e}"
            );
            return;
        }
        assert!(tmp.exists() && tmp.metadata().unwrap().len() > 0);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn save_sam_key() {
        let tmp = std::env::temp_dir().join("lmss-test-sam.hiv");
        let _ = std::fs::remove_file(&tmp);
        let r = save_registry_key("HKLM", "SAM", tmp.to_str().unwrap());
        match &r {
            Ok(()) => {
                assert!(tmp.exists() && tmp.metadata().unwrap().len() > 0);
                let _ = std::fs::remove_file(&tmp);
            }
            Err(e) => {
                // 非管理员会失败——不视为测试失败
                eprintln!("（非管理员环境 SAM 备份失败：{e}）");
            }
        }
    }
}

// ---- 2b. WMI 事件订阅查询（替代 powershell Get-CimInstance -Namespace root/subscription）----
//
// COM 直调 IWbemLocator → IWbemServices::ExecQuery，与 Get-CimInstance 同一条代码路径
// （cmdlet 底层即此 COM 接口），取证权威性零差异。
// windows-sys 0.48 的 Wmi 模块只有类型/常量没有方法函数，虚表按 wbemcli.h 原始
// 声明顺序自行定义（槽位顺序照抄头文件，未调用的槽位用占位类型保持布局）。

/// WMI 订阅条目：4 个类的公共字段超集，类不存在的字段为空串
#[derive(Debug)]
pub struct WmiSubEntry {
    pub class: String,        // __CLASS（如 __EventFilter）
    pub name: String,
    pub query: String,        // __EventFilter.Query
    pub command_line: String, // __CommandLineEventConsumer.CommandLineText
    pub script: String,       // ActiveScriptEventConsumer.ScriptText
    pub filter: String,       // __FilterToConsumerBinding.Filter（对象路径）
    pub consumer: String,     // __FilterToConsumerBinding.Consumer（对象路径）
}

type HResult = i32;

/// 未调用槽位的占位函数指针（仅保布局，不调用）
type UnusedFn = unsafe extern "system" fn();

/// IUnknown 前 3 槽（所有 COM 接口共用）
#[repr(C)]
struct ComHead {
    _query_interface: UnusedFn,
    _add_ref: UnusedFn,
    release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
}

#[repr(C)]
struct WbemLocatorVtbl {
    head: ComHead,
    connect_server: unsafe extern "system" fn(
        *mut core::ffi::c_void,      // self
        *const u16,                  // strNetworkResource (BSTR)
        *const u16,                  // strUser
        *const u16,                  // strPassword
        *const u16,                  // strLocale
        i32,                         // lSecurityFlags
        *const u16,                  // strAuthority
        *const core::ffi::c_void,    // pCtx
        *mut *mut core::ffi::c_void, // ppNamespace (IWbemServices)
    ) -> HResult,
}

#[repr(C)]
struct WbemServicesVtbl {
    head: ComHead,
    // 槽位 3-19：OpenNamespace … CreateInstanceEnumAsync（未调用，占位）
    _open_namespace: UnusedFn,
    _cancel_async_call: UnusedFn,
    _query_object_sink: UnusedFn,
    _get_object: UnusedFn,
    _get_object_async: UnusedFn,
    _put_class: UnusedFn,
    _put_class_async: UnusedFn,
    _delete_class: UnusedFn,
    _delete_class_async: UnusedFn,
    _create_class_enum: UnusedFn,
    _create_class_enum_async: UnusedFn,
    _put_instance: UnusedFn,
    _put_instance_async: UnusedFn,
    _delete_instance: UnusedFn,
    _delete_instance_async: UnusedFn,
    _create_instance_enum: UnusedFn,
    _create_instance_enum_async: UnusedFn,
    exec_query: unsafe extern "system" fn(
        *mut core::ffi::c_void,      // self
        *const u16,                  // strQueryLanguage (BSTR "WQL")
        *const u16,                  // strQuery (BSTR)
        i32,                         // lFlags
        *const core::ffi::c_void,    // pCtx
        *mut *mut core::ffi::c_void, // ppEnum (IEnumWbemClassObject)
    ) -> HResult,
}

#[repr(C)]
struct EnumWbemVtbl {
    head: ComHead,
    _reset: UnusedFn,
    next: unsafe extern "system" fn(
        *mut core::ffi::c_void,      // self
        i32,                         // lTimeout
        u32,                         // uCount
        *mut *mut core::ffi::c_void, // apObjects
        *mut u32,                    // puReturned
    ) -> HResult,
    _next_async: UnusedFn,
    _clone: UnusedFn,
    _skip: UnusedFn,
}

#[repr(C)]
struct WbemClassObjVtbl {
    head: ComHead,
    _get_qualifier_set: UnusedFn,
    get: unsafe extern "system" fn(
        *mut core::ffi::c_void,   // self
        *const u16,               // wszName (LPCWSTR)
        i32,                      // lFlags
        *mut core::ffi::c_void,   // pVal (VARIANT*)
        *mut i32,                 // pType (CIMTYPE)
        *mut i32,                 // plFlavor
    ) -> HResult,
    // Get 之后还有 20 个槽位（Put/Delete/…），全部未调用，无需占位（结构体布局只到已声明字段）
}

/// VARIANT ABI 兼容结构（x64：vt@0 + 3 保留 u16 + 8 字节联合体 = 16 字节）
#[repr(C)]
struct VarAbi {
    vt: u16,
    _reserved: [u16; 3],
    val: u64, // VT_BSTR → *mut u16；VT_UNKNOWN → 接口指针
}
const VT_EMPTY: u16 = 0;
const VT_BSTR: u16 = 8;
const VT_UNKNOWN: u16 = 13;

#[link(name = "oleaut32")]
extern "system" {
    fn SysAllocStringLen(str_in: *const u16, len: u32) -> *mut u16;
    fn SysStringLen(bstr: *mut u16) -> u32;
    fn SysFreeString(bstr: *mut u16) -> i32;
    fn VariantInit(pvarg: *mut VarAbi);
    fn VariantClear(pvarg: *mut VarAbi) -> HResult;
}

/// IID_IWbemLocator {DC12A687-737F-11CF-884D-00AA004B2E24}（wbemcli.h 原值）
const IID_IWBEM_LOCATOR: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0xDC12_A687,
    data2: 0x737F,
    data3: 0x11CF,
    data4: [0x88, 0x4D, 0x00, 0xAA, 0x00, 0x4B, 0x2E, 0x24],
};

/// 取接口对象的虚表指针
unsafe fn vt<T>(obj: *mut core::ffi::c_void) -> *mut T {
    *(obj as *mut *mut T)
}

unsafe fn com_release(obj: *mut core::ffi::c_void) {
    if !obj.is_null() {
        ((*vt::<ComHead>(obj)).release)(obj);
    }
}

fn alloc_bstr(s: &str) -> *mut u16 {
    let w: Vec<u16> = s.encode_utf16().collect();
    unsafe { SysAllocStringLen(w.as_ptr(), w.len() as u32) }
}

unsafe fn bstr_to_string(b: *mut u16) -> String {
    if b.is_null() {
        return String::new();
    }
    let len = SysStringLen(b) as usize;
    String::from_utf16_lossy(std::slice::from_raw_parts(b, len))
}

/// 读对象字符串属性（缺失/NULL → 空串）
unsafe fn wmi_get_str(obj: *mut core::ffi::c_void, prop: &str) -> String {
    let wname: Vec<u16> = prop.encode_utf16().chain(std::iter::once(0)).collect();
    let mut var = VarAbi { vt: VT_EMPTY, _reserved: [0; 3], val: 0 };
    VariantInit(&mut var);
    let hr = ((*vt::<WbemClassObjVtbl>(obj)).get)(
        obj, wname.as_ptr(), 0, &mut var as *mut _ as *mut core::ffi::c_void,
        std::ptr::null_mut(), std::ptr::null_mut(),
    );
    let out = if hr == 0 && var.vt == VT_BSTR && var.val != 0 {
        bstr_to_string(var.val as *mut u16)
    } else {
        String::new()
    };
    VariantClear(&mut var); // 释放 WMI 分配的 BSTR
    out
}

/// 读对象引用属性（如绑定的 Filter/Consumer）：punkVal 即目标 IWbemClassObject，
/// 取其 __RELPATH 还原为 `__EventFilter.Name="xxx"` 形式的绑定字符串
unsafe fn wmi_get_ref(obj: *mut core::ffi::c_void, prop: &str) -> String {
    let wname: Vec<u16> = prop.encode_utf16().chain(std::iter::once(0)).collect();
    let mut var = VarAbi { vt: VT_EMPTY, _reserved: [0; 3], val: 0 };
    VariantInit(&mut var);
    let hr = ((*vt::<WbemClassObjVtbl>(obj)).get)(
        obj, wname.as_ptr(), 0, &mut var as *mut _ as *mut core::ffi::c_void,
        std::ptr::null_mut(), std::ptr::null_mut(),
    );
    let out = if hr != 0 {
        String::new()
    } else if var.vt == VT_BSTR && var.val != 0 {
        // 引用属性常直接以对象路径 BSTR 返回（Win10 22H2 实测），
        // 形如 \\主机\root\subscription:__EventFilter.Name="SCM Event Log Filter"
        bstr_to_string(var.val as *mut u16)
    } else if var.vt == VT_UNKNOWN && var.val != 0 {
        // 亦可能返回内嵌 IWbemClassObject（punkVal）——取 __RELPATH 还原
        wmi_get_str(var.val as *mut core::ffi::c_void, "__RELPATH")
    } else {
        String::new()
    };
    VariantClear(&mut var); // 释放 BSTR / Release 引用的接口
    out
}

/// 查询 root\subscription 的 4 类事件订阅对象。
/// 等价于 `Get-CimInstance -Namespace root/subscription`（4 类逐一 ExecQuery），
/// 单类不存在（WBEM_E_INVALID_CLASS）时跳过——与 PS 版 SilentlyContinue 语义一致。
/// 仅基础设施失败（COM 初始化/连接不上）才返回 Err。
pub fn query_wmi_subscriptions() -> Result<Vec<WmiSubEntry>, String> {
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED,
    };
    unsafe {
        const RPC_E_CHANGED_MODE: HResult = 0x8001_0106u32 as i32;
        let hr = CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED);
        if hr < 0 && hr != RPC_E_CHANGED_MODE {
            return Err(format!("CoInitializeEx 失败：0x{:08X}", hr as u32));
        }
        let need_uninit = hr >= 0; // S_OK/S_FALSE 需配对 CoUninitialize
        let result = wmi_query_all();
        if need_uninit {
            CoUninitialize();
        }
        result
    }
}

unsafe fn wmi_query_all() -> Result<Vec<WmiSubEntry>, String> {
    use windows_sys::Win32::System::Com::{
        CoCreateInstance, CoSetProxyBlanket, CLSCTX_INPROC_SERVER,
        EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
    };
    use windows_sys::Win32::System::Wmi::{
        WbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    };

    let mut locator: *mut core::ffi::c_void = std::ptr::null_mut();
    let hr = CoCreateInstance(
        &WbemLocator,
        std::ptr::null_mut(),
        CLSCTX_INPROC_SERVER,
        &IID_IWBEM_LOCATOR,
        &mut locator,
    );
    if hr < 0 || locator.is_null() {
        return Err(format!("CoCreateInstance(WbemLocator) 失败：0x{:08X}", hr as u32));
    }

    let ns = alloc_bstr(r"root\subscription");
    let mut services: *mut core::ffi::c_void = std::ptr::null_mut();
    let hr = ((*vt::<WbemLocatorVtbl>(locator)).connect_server)(
        locator, ns,
        std::ptr::null(), std::ptr::null(), std::ptr::null(),
        0, std::ptr::null(), std::ptr::null_mut(),
        &mut services,
    );
    SysFreeString(ns);
    if hr < 0 || services.is_null() {
        com_release(locator);
        return Err(format!(r"ConnectServer(root\subscription) 失败：0x{:08X}（WMI 服务被禁用/损坏？）", hr as u32));
    }

    // 本地 WMI 代理需显式声明模拟级别（MS WMI 客户端样板；失败不致命）
    CoSetProxyBlanket(
        services,
        10, // RPC_C_AUTHN_WINNT
        0,  // RPC_C_AUTHZ_NONE
        std::ptr::null(),
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        std::ptr::null(),
        EOAC_NONE,
    );

    let mut out = Vec::new();
    const CLASSES: [&str; 4] = [
        "__EventFilter",
        "CommandLineEventConsumer",
        "ActiveScriptEventConsumer",
        "__FilterToConsumerBinding",
    ];
    for class in CLASSES {
        let wql = alloc_bstr("WQL");
        let query = alloc_bstr(&format!("SELECT * FROM {class}"));
        let mut enumerator: *mut core::ffi::c_void = std::ptr::null_mut();
        let hr = ((*vt::<WbemServicesVtbl>(services)).exec_query)(
            services, wql, query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            std::ptr::null(), &mut enumerator,
        );
        SysFreeString(wql);
        SysFreeString(query);
        if hr < 0 || enumerator.is_null() {
            continue; // 类不存在等 → 跳过该类（与 PS SilentlyContinue 一致）
        }

        // 上限防御：正常系统订阅数 < 100；Next 超时 15s 防止 WMI 服务异常时挂死
        for _ in 0..10_000 {
            let mut obj: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut returned: u32 = 0;
            let hr = ((*vt::<EnumWbemVtbl>(enumerator)).next)(
                enumerator, 15_000, 1, &mut obj, &mut returned,
            );
            if hr < 0 || returned == 0 {
                break; // 结束（WBEM_S_FALSE）或超时/出错——保留已取到的
            }
            let entry = WmiSubEntry {
                class: wmi_get_str(obj, "__CLASS"),
                name: wmi_get_str(obj, "Name"),
                query: wmi_get_str(obj, "Query"),
                command_line: wmi_get_str(obj, "CommandLineText"),
                script: wmi_get_str(obj, "ScriptText"),
                filter: wmi_get_ref(obj, "Filter"),
                consumer: wmi_get_ref(obj, "Consumer"),
            };
            com_release(obj);
            out.push(entry);
        }
        com_release(enumerator);
    }

    com_release(services);
    com_release(locator);
    Ok(out)
}

#[cfg(test)]
mod wmi_tests {
    use super::*;

    #[test]
    fn queries_root_subscription_namespace() {
        let subs = query_wmi_subscriptions().expect("WMI root\\subscription 查询应成功");
        assert!(!subs.is_empty(), "系统默认 SCM 订阅应存在：{subs:?}");
        assert!(
            subs.iter().any(|s| s.class == "__EventFilter"
                && s.name.eq_ignore_ascii_case("SCM Event Log Filter")),
            "应含基线 SCM Event Log Filter：{subs:?}"
        );
        // 绑定对象应还原出 Filter/Consumer 对象路径
        if let Some(b) = subs.iter().find(|s| s.class == "__FilterToConsumerBinding") {
            assert!(
                b.filter.contains("SCM Event Log Filter"),
                "默认绑定的 Filter 引用应指向 SCM Event Log Filter：{}",
                b.filter
            );
        }
    }
}
