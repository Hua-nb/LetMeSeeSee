use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "src/web/assets"]
pub struct Assets;

/// 路由判定结果（与 HTTP 细节解耦，便于单测）
#[derive(Debug, PartialEq)]
pub enum Route {
    Index,
    Asset(String),
    ApiScan,
    ApiVersion,
    ApiReg,
    ApiTaskXml,
    ApiOpen,
    Shutdown,
    Unauthorized,
    NotFound,
}

/// 路由 + 鉴权：/ 页面公开；/api/* 必须携带正确 ?t=token；静态资源不含数据，白名单公开
pub fn route(method: &str, raw_url: &str, token: &str) -> Route {
    let (path, query) = match raw_url.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw_url, ""),
    };
    if path == "/" {
        return Route::Index;
    }
    if path.starts_with("/api/") {
        let ok = query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .any(|(k, v)| k == "t" && v == token);
        if !ok {
            return Route::Unauthorized;
        }
        return match (method, path) {
            ("GET", "/api/scan") | ("POST", "/api/scan") => Route::ApiScan,
            ("GET", "/api/version") => Route::ApiVersion,
            ("GET", "/api/reg") => Route::ApiReg,
            ("GET", "/api/taskxml") => Route::ApiTaskXml,
            ("GET", "/api/open") => Route::ApiOpen,
            ("POST", "/api/shutdown") => Route::Shutdown,
            _ => Route::NotFound,
        };
    }
    // 静态资源：只允许白名单文件名，拒绝任何路径穿越
    match path.trim_start_matches('/') {
        "index.html" | "app.js" | "style.css" => {
            Route::Asset(path.trim_start_matches('/').to_string())
        }
        _ => Route::NotFound,
    }
}

pub fn asset_bytes(name: &str) -> Option<Vec<u8>> {
    Assets::get(name).map(|f| f.data.into_owned())
}

pub fn mime_of(name: &str) -> &'static str {
    match name {
        "index.html" => "text/html; charset=utf-8",
        "app.js" => "application/javascript; charset=utf-8",
        "style.css" => "text/css; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "a1b2c3d4e5f60718";

    #[test]
    fn index_is_public() {
        assert!(matches!(route("GET", "/?t=whatever", TOKEN), Route::Index));
        assert!(matches!(route("GET", "/", TOKEN), Route::Index));
    }

    #[test]
    fn api_requires_exact_token() {
        assert!(matches!(route("GET", "/api/scan?t=a1b2c3d4e5f60718", TOKEN), Route::ApiScan));
        assert!(matches!(route("GET", "/api/scan", TOKEN), Route::Unauthorized));
        assert!(matches!(route("GET", "/api/scan?t=wrong", TOKEN), Route::Unauthorized));
        assert!(matches!(route("GET", "/api/scan?t=a1b2c3d4e5f60718", "othertoken"), Route::Unauthorized));
    }

    #[test]
    fn shutdown_is_post_only() {
        assert!(matches!(route("POST", "/api/shutdown?t=a1b2c3d4e5f60718", TOKEN), Route::Shutdown));
        assert!(matches!(route("GET", "/api/shutdown?t=a1b2c3d4e5f60718", TOKEN), Route::NotFound));
    }

    #[test]
    fn static_assets_whitelist() {
        assert!(matches!(route("GET", "/app.js", TOKEN), Route::Asset(n) if n == "app.js"));
        assert!(matches!(route("GET", "/style.css", TOKEN), Route::Asset(n) if n == "style.css"));
        assert!(matches!(route("GET", "/../Cargo.toml", TOKEN), Route::NotFound));
    }

    #[test]
    fn version_endpoint_is_get_with_token() {
        assert!(matches!(route("GET", "/api/version?t=a1b2c3d4e5f60718", TOKEN), Route::ApiVersion));
        assert!(matches!(route("POST", "/api/version?t=a1b2c3d4e5f60718", TOKEN), Route::NotFound));
        assert!(matches!(route("GET", "/api/version", TOKEN), Route::Unauthorized));
    }

    #[test]
    fn reg_and_taskxml_require_token_and_get() {
        assert!(matches!(route("GET", "/api/reg?t=a1b2c3d4e5f60718&path=HKLM", TOKEN), Route::ApiReg));
        assert!(matches!(route("GET", "/api/reg", TOKEN), Route::Unauthorized));
        assert!(matches!(route("POST", "/api/reg?t=a1b2c3d4e5f60718", TOKEN), Route::NotFound));
        assert!(matches!(
            route("GET", "/api/taskxml?t=a1b2c3d4e5f60718&ref=x", TOKEN),
            Route::ApiTaskXml
        ));
        assert!(matches!(route("GET", "/api/taskxml", TOKEN), Route::Unauthorized));
    }

    #[test]
    fn open_endpoint_requires_token_and_get() {
        assert!(matches!(route("GET", "/api/open?t=a1b2c3d4e5f60718&tool=taskschd", TOKEN), Route::ApiOpen));
        assert!(matches!(route("GET", "/api/open", TOKEN), Route::Unauthorized));
        assert!(matches!(route("POST", "/api/open?t=a1b2c3d4e5f60718", TOKEN), Route::NotFound));
    }

    #[test]
    fn unknown_path_is_404() {
        assert!(matches!(route("GET", "/nope", TOKEN), Route::NotFound));
    }
}
