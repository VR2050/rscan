// DNS 结构体用于子域名爆破
use crate::models::request_data::RequestParms;
use crate::services::web_scan::live_scan::ping;
use reqwest::Result;
pub struct DNS<'a> {
    pub request_base: RequestParms<'a>,
    pub dns_url: &'a str,
}

impl<'a> DNS<'a> {
    // 子域名爆破方法
    async fn sub_blasting(request: DNS<'a>, dns_url: &str) -> Result<String> {
        let url = format!("http://{}.{}", request.request_base.url, dns_url);

        let result = ping(
            request.request_base.client,
            &url,
            request.request_base.method,
        )
        .await;
        if result.is_ok() {
            result
        } else {
            let response = reqwest::get(&url).await?;
            Ok(response.url().to_string())
        }
    }
}
