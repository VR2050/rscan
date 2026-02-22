use reqwest::{Response, header::HeaderMap};

/// Generic PoC matcher container.
#[derive(Debug, Clone)]
pub struct PocScan<F, T>
where
    F: Fn(&Response, &T) -> bool,
{
    pub poc: HeaderMap,
    pub scan_func: F,
    pub scan_match: T,
}

impl<F, T> PocScan<F, T>
where
    F: Fn(&Response, &T) -> bool,
{
    pub fn new(poc: HeaderMap, scan_func: F, scan_match: T) -> Self {
        Self {
            poc,
            scan_func,
            scan_match,
        }
    }

    pub fn evaluate(&self, response: &Response) -> bool {
        (self.scan_func)(response, &self.scan_match)
    }
}

// Backward-compatible alias with original name.
pub type POCSCAN<F, T> = PocScan<F, T>;
