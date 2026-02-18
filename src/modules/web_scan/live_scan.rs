// 发送一个请求，检查指定 URL 是否存活（返回成功状态码）
use reqwest::{Client, Method, Result};
pub async fn ping(client: &Client, url: &str, method: Method) -> Result<String> {
    let response = client.request(method, url).send().await?;

    if response.status().is_success() {
        Ok(format!("the url: {} alive", url))
    } else {
        Ok(format!("the url: {} dead", url))
    }
}
