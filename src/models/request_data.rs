// 定义请求数据的类型，支持查询参数、表单、JSON 和无数据

use serde_json::Value;
use serde_json::from_str;
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
