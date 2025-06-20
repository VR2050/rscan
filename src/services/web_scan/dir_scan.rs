use crate::models::request_data::{Data,RequestParms,Crawl};
use reqwest::Result;

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
