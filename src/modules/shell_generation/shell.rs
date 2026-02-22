use crate::errors::RustpenError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellPlatform {
    Bash,
    Python,
    Powershell,
}

impl ShellPlatform {
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "bash" | "sh" => Some(Self::Bash),
            "python" | "py" => Some(Self::Python),
            "powershell" | "ps" | "pwsh" => Some(Self::Powershell),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReverseShellSpec {
    pub lhost: String,
    pub lport: u16,
    pub platform: ShellPlatform,
}

#[derive(Debug, Clone)]
pub struct SafeShellPlaybook {
    pub platform: ShellPlatform,
    pub payload_placeholder: String,
    pub safety_notice: String,
    pub info_collection: Vec<String>,
    pub privilege_escalation_notes: Vec<String>,
    pub next_steps: Vec<String>,
}

impl SafeShellPlaybook {
    pub fn render(&self) -> String {
        let mut out = Vec::new();
        out.push(format!("[SIMULATED] platform={:?}", self.platform));
        out.push(self.safety_notice.clone());
        out.push(format!("payload_placeholder: {}", self.payload_placeholder));
        out.push("info_collection:".to_string());
        for item in &self.info_collection {
            out.push(format!("- {}", item));
        }
        out.push("privilege_escalation_notes:".to_string());
        for item in &self.privilege_escalation_notes {
            out.push(format!("- {}", item));
        }
        out.push("next_steps:".to_string());
        for item in &self.next_steps {
            out.push(format!("- {}", item));
        }
        out.join("\n")
    }
}

pub fn build_safe_playbook(spec: &ReverseShellSpec) -> Result<SafeShellPlaybook, RustpenError> {
    if spec.lhost.trim().is_empty() {
        return Err(RustpenError::MissingArgument {
            arg: "lhost".to_string(),
        });
    }
    if spec.lport == 0 {
        return Err(RustpenError::InvalidPort {
            input: spec.lport.to_string(),
        });
    }

    let platform = spec.platform;
    let payload_placeholder = format!(
        "SAFE_PLACEHOLDER:{}:{}:{}",
        match platform {
            ShellPlatform::Bash => "bash",
            ShellPlatform::Python => "python",
            ShellPlatform::Powershell => "powershell",
        },
        spec.lhost,
        spec.lport
    );

    let safety_notice = "This module emits non-operational placeholders only. Use authorized tooling and follow legal/organizational approvals.".to_string();

    let info_collection = vec![
        "Record OS version, hostname, and network interfaces using approved inventory tools."
            .to_string(),
        "Collect running services and listening ports via sanctioned monitoring sources."
            .to_string(),
        "Capture security control posture (EDR/AV/firewall) through documented endpoints."
            .to_string(),
    ];

    let privilege_escalation_notes = vec![
        "Review patch level against known fixed issues (no exploitation guidance).".to_string(),
        "Identify misconfigurations via approved compliance baselines.".to_string(),
        "Validate least-privilege and access boundaries with owners.".to_string(),
    ];

    let next_steps = vec![
        "Obtain written authorization before any active testing.".to_string(),
        "Prefer passive verification where possible.".to_string(),
        "Log all actions for audit and incident response.".to_string(),
    ];

    Ok(SafeShellPlaybook {
        platform,
        payload_placeholder,
        safety_notice,
        info_collection,
        privilege_escalation_notes,
        next_steps,
    })
}

pub fn build_reverse_shell(spec: &ReverseShellSpec) -> Result<String, RustpenError> {
    let playbook = build_safe_playbook(spec)?;
    Ok(playbook.render())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_bash_shell() {
        let s = build_reverse_shell(&ReverseShellSpec {
            lhost: "127.0.0.1".to_string(),
            lport: 4444,
            platform: ShellPlatform::Bash,
        })
        .unwrap();
        assert!(s.contains("SAFE_PLACEHOLDER:bash:127.0.0.1:4444"));
        assert!(s.contains("[SIMULATED]"));
    }

    #[test]
    fn parse_platform_works() {
        assert_eq!(ShellPlatform::parse("bash"), Some(ShellPlatform::Bash));
        assert_eq!(ShellPlatform::parse("py"), Some(ShellPlatform::Python));
        assert_eq!(
            ShellPlatform::parse("powershell"),
            Some(ShellPlatform::Powershell)
        );
        assert_eq!(ShellPlatform::parse("unknown"), None);
    }
}
