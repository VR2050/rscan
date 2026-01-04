use crate::errors::RustpenError;
use scraper::{Html, Selector};
use url::Url;

#[derive(Debug, Clone)]
pub struct ParsedPage {
    pub base: Url,
    pub links: Vec<String>,
}

pub struct Parser;

impl Parser {
    pub fn parse(base_url: &str, body: &str) -> Result<ParsedPage, RustpenError> {
        let base = Url::parse(base_url).map_err(|e| RustpenError::ParseError(format!("{}", e)))?;
        let document = Html::parse_document(body);
        let selector = Selector::parse("a[href]").map_err(|e| RustpenError::ParseError(format!("{}", e)))?;
        let mut links = Vec::new();
        for el in document.select(&selector) {
            if let Some(href) = el.value().attr("href") {
                if let Ok(resolved) = base.join(href) {
                    links.push(resolved.into_string())
                }
            }
        }
        Ok(ParsedPage { base, links })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_links() {
        let html = r#"
        <html>
            <body>
                <a href="/a.html">A</a>
                <a href="http://example.org/b">B</a>
                <a>nohref</a>
            </body>
        </html>
        "#;
        let parsed = Parser::parse("http://example.com/", html).unwrap();
        assert!(parsed.links.contains(&"http://example.com/a.html".to_string()));
        assert!(parsed.links.contains(&"http://example.org/b".to_string()));
        assert_eq!(parsed.links.len(), 2);
    }
}
