use reqwest::Result;
use reqwest::header::HeaderMap;
use reqwest::{Client, Method, Response};
use serde_json::Value;
use serde_json::from_str;

mod services;
mod models;
// 发送一个请求，检查指定 URL 是否存活（返回成功状态码）
pub async fn ping(client: &Client, url: &str, method: Method) -> Result<String> {
    let response = client.request(method, url).send().await?;

    if response.status().is_success() {
        Ok(format!("the url: {} alive", url))
    } else {
        Ok(format!("the url: {} dead", url))
    }
}


// 定义请求数据的类型，支持查询参数、表单、JSON 和无数据
#[derive(Debug, Clone)]
pub enum Data<'a> {
    Query(Vec<(&'a str, &'a str)>), // 查询参数键值对
    Form(Vec<(&'a str, &'a str)>),  // 表单数据键值对
    Json(Value),                    // JSON 数据结构
    None,
}

impl<'a> Data<'a> {
    /// 将字符串形式的查询参数转换为 `Query` 枚举变体
    pub fn string_to_query_and_form(s: &'a str) -> Vec<(&'a str, &'a str)> {
        s.trim() // 去除首尾空白字符
            .split('&') // 按 "&" 分割
            .filter_map(|pair| {
                let mut parts = pair.split('=');
                // 提取键和值
                let key = parts.next()?.trim();
                let value = parts.next()?.trim();
                Some((key, value))
            })
            .collect() // 收集为 Vec<(&str, &str)>
    }

    /// 将字符串解析为 JSON Value
    pub fn string_to_json(s: &'a str) -> Value {
        match from_str::<Value>(s) {
            Ok(json_value) => json_value, // 成功解析，返回 Value
            Err(e) => {
                eprintln!("Failed to parse JSON: {}", e); // 打印错误信息
                Value::Null // 返回空 JSON 值
            }
        }
    }
}

// 请求参数结构体，包含客户端、URL、方法和数据
#[derive(Debug, Clone)]
pub struct RequestParms<'a> {
    pub request_data: Data<'a>,
    pub url: &'a str,
    pub client: &'a Client,
    pub method: Method,
}

// DIR 结构体用于目录扫描任务
pub struct DIR<'a> {
    pub request_base: RequestParms<'a>,
}

// 实现 Crawl trait 给 DIR 类型，提供不同的爬取方式
impl<'a> Crawl<DIR<'a>, (String, u16, Option<u64>)> for DIR<'a> {
    // 基础爬取方法，发送请求并返回结果（url, 状态码, 内容长度）
    async fn crawl(request: DIR<'a>, url: &str) -> Result<(String, u16, Option<u64>)> {
        let response = request
            .request_base
            .client
            .request(request.request_base.method, url)
            .send()
            .await?;
        let status = response.status().as_u16();
        let url = response.url().to_string();
        let content_length = response.content_length();
        Ok((url, status, content_length))
    }

    // 使用表单数据进行请求
    async fn crawl_with_form(
        request: DIR<'a>,
        url: &str,
        request_data: Data<'_>,
    ) -> Result<(String, u16, Option<u64>)> {
        if let Data::Form(form) = request_data {
            let response = request
                .request_base
                .client
                .request(request.request_base.method, url)
                .form(&form)
                .send()
                .await?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_length = response.content_length();
            Ok((url, status, content_length))
        } else {
            Ok(("sth wrong".to_owned(), 0, Some(0)))
        }
    }

    // 使用查询参数进行请求
    async fn crawl_with_query(
        request: DIR<'a>,
        url: &str,
        request_data: Data<'_>,
    ) -> Result<(String, u16, Option<u64>)> {
        if let Data::Query(query) = request_data {
            let response = request
                .request_base
                .client
                .request(request.request_base.method, url)
                .query(&query)
                .send()
                .await?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_length = response.content_length();
            Ok((url, status, content_length))
        } else {
            Ok(("sth wrong".to_owned(), 0, Some(0)))
        }
    }

    // 使用 JSON 数据进行请求
    async fn crawl_with_json(
        request: DIR<'a>,
        url: &str,
        request_data: Data<'_>,
    ) -> Result<(String, u16, Option<u64>)> {
        if let Data::Json(json) = request_data {
            let response = request
                .request_base
                .client
                .request(request.request_base.method, url)
                .json(&json)
                .send()
                .await?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_length = response.content_length();
            Ok((url, status, content_length))
        } else {
            Ok(("sth wrong".to_owned(), 0, Some(0)))
        }
    }
}

// FUZZ 结构体用于模糊测试任务，替换 URL 中的 "FUZZ" 占位符
pub struct FUZZ<'a> {
    pub request_base: RequestParms<'a>,
    pub fuzzed_keywords: &'a str,
}

// 实现 Crawl trait 给 FUZZ 类型
impl<'a> Crawl<FUZZ<'a>, (String, u16, Option<u64>)> for FUZZ<'a> {
    // 替换 URL 中的 "FUZZ" 后发送请求
    async fn crawl(request: FUZZ<'a>, url: &str) -> Result<(String, u16, Option<u64>)> {
        let url = url.replace("FUZZ", request.fuzzed_keywords);
        let response = request
            .request_base
            .client
            .request(request.request_base.method, url)
            .send()
            .await?;
        let status = response.status().as_u16();
        let url = response.url().to_string();
        let content_length = response.content_length();
        Ok((url, status, content_length))
    }

    // 替换 URL 并使用查询参数发送请求
    async fn crawl_with_query(
        request: FUZZ<'a>,
        url: &str,
        request_data: Data<'_>,
    ) -> Result<(String, u16, Option<u64>)> {
        if let Data::Query(query) = request_data {
            let url = url.replace("FUZZ", request.fuzzed_keywords);
            let response = request
                .request_base
                .client
                .request(request.request_base.method, url)
                .query(&query)
                .send()
                .await?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_length = response.content_length();
            Ok((url, status, content_length))
        } else {
            Ok(("sth wrong".to_owned(), 0, Some(0)))
        }
    }

    // 替换 URL 并使用表单数据发送请求
    async fn crawl_with_form(
        request: FUZZ<'a>,
        url: &str,
        request_data: Data<'_>,
    ) -> Result<(String, u16, Option<u64>)> {
        if let Data::Form(form) = request_data {
            let url = url.replace("FUZZ", request.fuzzed_keywords);
            let response = request
                .request_base
                .client
                .request(request.request_base.method, url)
                .form(&form)
                .send()
                .await?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_length = response.content_length();
            Ok((url, status, content_length))
        } else {
            Ok(("sth wrong".to_owned(), 0, Some(0)))
        }
    }

    // 替换 URL 并使用 JSON 数据发送请求
    async fn crawl_with_json(
        request: FUZZ<'a>,
        url: &str,
        request_data: Data<'_>,
    ) -> Result<(String, u16, Option<u64>)> {
        if let Data::Json(json) = request_data {
            let url = url.replace("FUZZ", request.fuzzed_keywords);
            let response = request
                .request_base
                .client
                .request(request.request_base.method, url)
                .json(&json)
                .send()
                .await?;
            let status = response.status().as_u16();
            let url = response.url().to_string();
            let content_length = response.content_length();
            Ok((url, status, content_length))
        } else {
            Ok(("sth wrong".to_owned(), 0, Some(0)))
        }
    }
}

// DNS 结构体用于子域名爆破
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

// POCSCAN 结构体用于漏洞检测，携带 HTTP 头部、匹配函数和匹配值
pub struct POCSCAN<F, T>
where
    F: Fn(&Response, T) -> bool,
{
    pub poc: HeaderMap,
    pub scan_func: F,      // 扫描匹配函数
    pub scan_match: T,     // 匹配值
}

// Crawl trait 定义了不同请求方式的行为
pub trait Crawl<T, U> {
    async fn crawl(request: T, url: &str) -> Result<U>;
    async fn crawl_with_query(request: T, url: &str, request_data: Data<'_>) -> Result<U>;
    async fn crawl_with_json(request: T, url: &str, request_data: Data<'_>) -> Result<U>;
    async fn crawl_with_form(request: T, url: &str, request_data: Data<'_>) -> Result<U>;
}

fn main() {}