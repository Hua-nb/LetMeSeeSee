mod encoding;
mod evtxdata;
mod model;
mod pf_mam;
mod proctree;
mod regbrowse;
mod shellitem;
mod suspicion;
mod modules;
mod regutil;
mod timeutil;
mod verinfo;
mod winapi;
mod web;

use getrandom::getrandom;
use tiny_http::{Header, Response};

fn main() {
    // 默认请求管理员权限（解锁 Prefetch/Security/BAM/AmCache 等关键证据源）。
    // --no-elevate 跳过（开发/自动化场景）。
    let no_elevate = std::env::args().any(|a| a == "--no-elevate");
    // 自检模式：打印提权状态并退出（验证/诊断用）
    if std::env::args().any(|a| a == "--check-elevated") {
        println!("elevated={}", crate::regutil::is_elevated());
        return;
    }
    // 防循环保险：提权重启出来的子进程绝不再触发提权
    let from_elevate = std::env::args().any(|a| a == "--from-elevate");
    if from_elevate && !crate::regutil::is_elevated() {
        println!("提权后仍检测为普通权限（异常），以降级模式继续，不再请求提权。");
    }
    if !no_elevate && !from_elevate && !crate::regutil::is_elevated() {
        println!("检测到普通权限：正在请求管理员权限（Prefetch/安全日志/AmCache/BAM 需要它）…");
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !exe.is_empty() && runas(&exe, "--from-elevate") {
            println!("已以管理员身份重新启动，当前窗口即将退出。");
            std::process::exit(0);
        }
        println!(
            "未获得管理员权限，将以降级模式运行（部分证据源不可读，界面顶部会有提示）。\n按 Ctrl+C 退出后可右键选择『以管理员身份运行』。"
        );
    }
    let token = gen_token();
    let (server, port) = bind_random_loopback();
    let url = format!("http://127.0.0.1:{port}/?t={token}");
    println!("Let me see see 正在运行");
    println!("若浏览器未自动打开，请手动访问：{url}");
    println!("本服务仅监听 127.0.0.1，不会对外网/局域网暴露");
    println!("按 Ctrl+C 退出\n");
    let _ = webbrowser::open(&url);
    let mut cached: Option<model::ScanReport> = None;

    for mut request in server.incoming_requests() {
        let route = web::route(request.method().as_str(), request.url(), &token);
        match route {
            web::Route::Shutdown => {
                let _ = request.respond(Response::from_string("bye").with_status_code(200));
                println!("收到退出请求，Let me see see 已退出");
                std::process::exit(0);
            }
            web::Route::Index => respond(
                request,
                200,
                "text/html; charset=utf-8",
                web::asset_bytes("index.html").unwrap_or_default(),
            ),
            web::Route::Asset(name) => match web::asset_bytes(&name) {
                Some(b) => respond(request, 200, web::mime_of(&name), b),
                None => respond(
                    request,
                    404,
                    "text/plain; charset=utf-8",
                    b"not found".to_vec(),
                ),
            },
            web::Route::ApiScan => {
                // 可选 group= 参数：仅重扫指定大类并与缓存合并
                let group = query_param(request.url(), "group");
                let report = modules::scan_into(&mut cached, group.as_deref());
                let body = serde_json::to_vec(&report).unwrap();
                respond(request, 200, "application/json; charset=utf-8", body);
            }
            web::Route::ApiVersion => respond(
                request,
                200,
                "text/plain; charset=utf-8",
                env!("CARGO_PKG_VERSION").as_bytes().to_vec(),
            ),
            // 注册表浏览器：GET /api/reg?path=HKLM\SOFTWARE&t=…
            web::Route::ApiReg => {
                let path = query_param(request.url(), "path").unwrap_or_default();
                let body = match regbrowse::browse(&path) {
                    Ok(r) => serde_json::to_vec(&r).unwrap_or_default(),
                    Err(e) => serde_json::to_vec(&serde_json::json!({ "error": e }))
                        .unwrap_or_default(),
                };
                respond(request, 200, "application/json; charset=utf-8", body);
            }
            // 任务完整 XML：GET /api/taskxml?ref=相对路径&t=…
            web::Route::ApiTaskXml => {
                let rel = query_param(request.url(), "ref").unwrap_or_default();
                let safe = !rel.is_empty()
                    && !rel.contains("..")
                    && !rel.contains(':')
                    && !rel.starts_with('\\');
                let body = if safe {
                    let p = std::path::Path::new(r"C:\Windows\System32\Tasks").join(&rel);
                    match std::fs::read(&p)
                        .ok()
                        .and_then(|b| modules::schtasks::decode_task_xml(&b))
                    {
                        Some(xml) => serde_json::to_vec(&serde_json::json!({ "xml": xml }))
                            .unwrap_or_default(),
                        None => serde_json::to_vec(
                            &serde_json::json!({ "error": format!("任务文件不可读：{rel}") }),
                        )
                        .unwrap_or_default(),
                    }
                } else {
                    serde_json::to_vec(&serde_json::json!({ "error": "非法任务路径" }))
                        .unwrap_or_default()
                };
                respond(request, 200, "application/json; charset=utf-8", body);
            }
            // 打开 Windows 原生管理工具：GET /api/open?tool=taskschd&t=…
            web::Route::ApiOpen => {
                let tool = query_param(request.url(), "tool").unwrap_or_default();
                let ok = regutil::open_native_tool(&tool);
                let body = serde_json::to_vec(&serde_json::json!({ "ok": ok }))
                    .unwrap_or_default();
                respond(request, 200, "application/json; charset=utf-8", body);
            }
            web::Route::Unauthorized => respond(
                request,
                401,
                "text/plain; charset=utf-8",
                b"unauthorized".to_vec(),
            ),
            web::Route::NotFound => respond(
                request,
                404,
                "text/plain; charset=utf-8",
                b"not found".to_vec(),
            ),
        }
    }
}

/// 从 URL 查询串取参数（已 URL 解码）
fn query_param(raw_url: &str, key: &str) -> Option<String> {
    raw_url.split('?').nth(1)?.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| urldecode(v))
    })
}

fn respond(request: tiny_http::Request, status: u16, mime: &str, body: Vec<u8>) {
    let header = Header::from_bytes(&b"Content-Type"[..], mime.as_bytes()).unwrap();
    let resp = Response::from_data(body)
        .with_status_code(status)
        .with_header(header)
        .with_header(Header::from_bytes(&b"Cache-Control"[..], &b"no-store"[..]).unwrap());
    let _ = request.respond(resp);
}

/// URL 百分号解码（group 参数含中文）
fn urldecode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => { out.push(v); i += 3; }
                    None => { out.push(b[i]); i += 1; }
                }
            }
            b'+' => { out.push(b' '); i += 1; }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// ShellExecute "runas"：触发 UAC 提权重启；成功返回 true
fn runas(exe: &str, extra_arg: &str) -> bool {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let op: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let file: Vec<u16> = exe.encode_utf16().chain(std::iter::once(0)).collect();
    let rc = unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            {
                let args: Vec<u16> = extra_arg.encode_utf16().chain(std::iter::once(0)).collect();
                args.as_ptr()
            },
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    (rc as isize) > 32
}

/// 8 字节随机数的十六进制，作为会话 token
fn gen_token() -> String {
    let mut buf = [0u8; 8];
    getrandom(&mut buf).expect("生成随机 token 失败");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// 在回环地址上随机尝试端口，绑定成功即用
fn bind_random_loopback() -> (tiny_http::Server, u16) {
    for _ in 0..64 {
        let mut b = [0u8; 2];
        let _ = getrandom(&mut b);
        let port = 20000 + (u16::from_le_bytes(b) % 40000);
        if let Ok(server) = tiny_http::Server::http(format!("127.0.0.1:{port}")) {
            return (server, port);
        }
    }
    panic!("64 次随机端口绑定均失败");
}
