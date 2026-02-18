use crate::cores::engine::scan_result::ScanStatus;
use crate::cores::host::PortStatus;

pub(crate) fn map_port_status(is_open: bool, status: Option<PortStatus>) -> ScanStatus {
    if is_open {
        return ScanStatus::Open;
    }
    match status {
        Some(PortStatus::Closed) => ScanStatus::Closed,
        Some(PortStatus::Filtered) => ScanStatus::Filtered,
        Some(PortStatus::Error) => ScanStatus::Error,
        _ => ScanStatus::Unknown,
    }
}
