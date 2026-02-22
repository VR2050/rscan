use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};

use crate::errors::RustpenError;

#[derive(Debug, Clone)]
pub struct FuzzAttackConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
}

impl Default for FuzzAttackConfig {
    fn default() -> Self {
        Self {
            concurrency: 16,
            timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzAttackHit {
    pub url: String,
    pub payload: String,
    pub status: u16,
    pub content_len: u64,
}

pub async fn run_simple_fuzz_attack(
    url_template: &str,
    payloads: &[String],
    cfg: FuzzAttackConfig,
) -> Result<Vec<FuzzAttackHit>, RustpenError> {
    if !url_template.contains("FUZZ") {
        return Err(RustpenError::ParseError(
            "url template must contain FUZZ placeholder".to_string(),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(cfg.timeout_ms))
        .build()
        .map_err(|e| RustpenError::NetworkError(e.to_string()))?;

    let mut stream = stream::iter(payloads.iter().cloned().map(|payload| {
        let client = client.clone();
        let url = url_template.replace("FUZZ", &payload);
        async move {
            let resp = client.get(&url).send().await;
            (url, payload, resp)
        }
    }))
    .buffer_unordered(cfg.concurrency.max(1));

    let mut out = Vec::new();
    while let Some((url, payload, resp)) = stream.next().await {
        if let Ok(resp) = resp {
            let status = resp.status().as_u16();
            let content_len = resp.content_length().unwrap_or(0);
            out.push(FuzzAttackHit {
                url,
                payload,
                status,
                content_len,
            });
        }
    }
    Ok(out)
}
