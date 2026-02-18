modules::web_scan helpers

Exported functions:
- `run_dir_scan(base, paths, FetcherConfig) -> Vec<(url, status, content_len)>`
- `run_fuzz_scan(url_with_FUZZ, keywords, FetcherConfig) -> Vec<(url, status, content_len)>`
- `run_subdomain_burst(domain, words, FetcherConfig) -> Vec<String>`

These functions are thin wrappers around `cores::web::Fetcher` and return results in a simple structure suitable for CLI output and further processing.