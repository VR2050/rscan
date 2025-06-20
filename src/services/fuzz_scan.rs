// FUZZ 结构体用于模糊测试任务，替换 URL 中的 "FUZZ" 占位符
use crate::models::request_data::{RequestParms,Data,Crawl};
use reqwest::Result;
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

