fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "windows" {
        return;
    }
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "1.0.0".to_string());
    let fv = format!("{ver}.0");
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set("FileDescription", "Let me see see (incident response timeline)");
    res.set("ProductName", "Let me see see");
    res.set("OriginalFilename", "LetMeSeeSee.exe");
    res.set("LegalCopyright", "For authorized incident response & security audit use only");
    res.set("FileVersion", &fv);
    res.set("ProductVersion", &fv);
    res.compile().unwrap();
}
