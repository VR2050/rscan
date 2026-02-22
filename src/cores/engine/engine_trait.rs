use tokio::sync::mpsc;

use super::scan_job::ScanJob;
use super::scan_result::ScanResult;
use crate::errors::RustpenError;

pub trait ScanEngine: Send + Sync {
    fn name(&self) -> &str;
    fn submit(&self, job: ScanJob) -> Result<(), RustpenError>;
    fn submit_many<I>(&self, jobs: I) -> Result<(), RustpenError>
    where
        I: IntoIterator<Item = ScanJob>,
    {
        for job in jobs {
            self.submit(job)?;
        }
        Ok(())
    }
    fn take_results(&mut self) -> Result<mpsc::Receiver<ScanResult>, RustpenError>;
}
