pub mod shell_generation;

pub mod port_scan;
pub mod reverse;
pub mod vuln_check;
pub mod web_scan;

// 导出模块级 API
pub use port_scan::ports::HostScanner;

// 模块级 web 扫描封装
pub use web_scan::WebScanner;
