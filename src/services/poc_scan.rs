// POCSCAN 结构体用于漏洞检测，携带 HTTP 头部、匹配函数和匹配值
use reqwest::{Response, header::HeaderMap};
pub struct POCSCAN<F, T>
where
    F: Fn(&Response, T) -> bool,
{
    pub poc: HeaderMap,
    pub scan_func: F,  // 扫描匹配函数
    pub scan_match: T, // 匹配值
}
