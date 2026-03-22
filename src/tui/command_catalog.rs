pub(crate) fn launcher_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Host Quick (127.0.0.1)", "h.quick 127.0.0.1"),
        ("Host TCP 22,80,443", "h.tcp 127.0.0.1 22,80,443"),
        (
            "Web Dir example.com",
            "w.dir https://example.com /,/robots.txt",
        ),
        (
            "Web Fuzz example.com/FUZZ",
            "w.fuzz https://example.com/FUZZ admin,login",
        ),
        ("Web DNS example.com", "w.dns example.com www,api,dev"),
        ("Vuln Scan example.com", "v.scan https://example.com"),
        ("Reverse Analyze /bin/ls", "r.analyze /bin/ls"),
        ("Reverse Plan /bin/ls", "r.plan /bin/ls objdump"),
        ("Reverse Run /bin/ls", "r.run /bin/ls ghidra full"),
        ("Focus Reverse Tab", "zfocus reverse"),
    ]
}

pub(crate) fn completion_heads() -> &'static [&'static str] {
    &[
        "h.quick",
        "h.tcp",
        "w.dir",
        "w.fuzz",
        "w.dns",
        "v.scan",
        "r.analyze",
        "r.plan",
        "r.run",
        "zrun",
        "zlogs",
        "zshell",
        "zart",
        "zrev",
        "zfocus",
        "host",
        "web",
        "vuln",
        "reverse",
    ]
}
