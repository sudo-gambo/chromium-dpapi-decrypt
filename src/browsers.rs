


pub struct BrowserInfo {
    pub name: &'static str,
    pub local_state_dir: &'static str,
}

pub const BROWSERS: &[BrowserInfo] = &[
    BrowserInfo {
        name: "chrome",
        local_state_dir: "Google\\Chrome\\User Data",
    },
    BrowserInfo {
        name: "edge",
        local_state_dir: "Microsoft\\Edge\\User Data",
    },
    BrowserInfo {
        name: "brave",
        local_state_dir: "BraveSoftware\\Brave-Browser\\User Data",
    },
];