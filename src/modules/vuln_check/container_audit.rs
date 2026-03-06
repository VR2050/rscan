use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::RustpenError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAuditFinding {
    pub file: PathBuf,
    pub object: String,
    pub severity: String,
    pub rule: String,
    pub message: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAuditReport {
    pub files_scanned: usize,
    pub objects_scanned: usize,
    pub findings: Vec<ContainerAuditFinding>,
    pub errors: Vec<String>,
}

pub fn audit_container_manifests_from_path(
    path: impl AsRef<Path>,
) -> Result<ContainerAuditReport, RustpenError> {
    let path = path.as_ref();
    let files = if path.is_dir() {
        let mut out = Vec::new();
        collect_manifest_files(path, &mut out)?;
        out.sort();
        out
    } else {
        vec![path.to_path_buf()]
    };

    let mut report = ContainerAuditReport {
        files_scanned: 0,
        objects_scanned: 0,
        findings: Vec::new(),
        errors: Vec::new(),
    };

    for file in files {
        report.files_scanned += 1;
        match parse_manifest_documents(&file) {
            Ok(docs) => {
                for doc in docs {
                    scan_document(&file, &doc, &mut report);
                }
            }
            Err(e) => report.errors.push(format!("{}: {}", file.display(), e)),
        }
    }

    Ok(report)
}

fn is_supported_manifest_file(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    ext.eq_ignore_ascii_case("yaml")
        || ext.eq_ignore_ascii_case("yml")
        || ext.eq_ignore_ascii_case("json")
}

fn collect_manifest_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), RustpenError> {
    for entry in std::fs::read_dir(dir).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let path = entry.path();
        let ty = entry.file_type().map_err(RustpenError::Io)?;
        if ty.is_dir() {
            collect_manifest_files(&path, out)?;
        } else if ty.is_file() && is_supported_manifest_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn parse_manifest_documents(path: &Path) -> Result<Vec<serde_yaml::Value>, RustpenError> {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default();
    let text = std::fs::read_to_string(path).map_err(RustpenError::Io)?;
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    if ext.eq_ignore_ascii_case("json") {
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| RustpenError::ParseError(e.to_string()))?;
        let doc =
            serde_yaml::to_value(json).map_err(|e| RustpenError::ParseError(e.to_string()))?;
        return Ok(vec![doc]);
    }

    let mut docs = Vec::new();
    for d in serde_yaml::Deserializer::from_str(&text) {
        let doc = serde_yaml::Value::deserialize(d)
            .map_err(|e| RustpenError::ParseError(e.to_string()))?;
        if !doc.is_null() {
            docs.push(doc);
        }
    }
    Ok(docs)
}

fn scan_document(file: &Path, doc: &serde_yaml::Value, report: &mut ContainerAuditReport) {
    if let Some(kind) = get_str(doc, "kind") {
        if kind.eq_ignore_ascii_case("list")
            && let Some(items) = get_value(doc, "items").and_then(|v| v.as_sequence())
        {
            for item in items {
                scan_workload_object(file, item, report);
            }
            return;
        }
    }
    scan_workload_object(file, doc, report);
}

fn scan_workload_object(file: &Path, obj: &serde_yaml::Value, report: &mut ContainerAuditReport) {
    if !obj.is_mapping() {
        return;
    }
    report.objects_scanned += 1;
    let object = object_label(obj);

    if let Some((pod_spec, spec_path)) = extract_pod_spec(obj) {
        audit_pod_spec(
            file,
            &object,
            pod_spec,
            spec_path,
            &mut report.findings,
            &mut report.errors,
        );
    }
}

fn extract_pod_spec(obj: &serde_yaml::Value) -> Option<(&serde_yaml::Value, &'static str)> {
    let kind = get_str(obj, "kind")?.to_ascii_lowercase();
    match kind.as_str() {
        "pod" => get_value(obj, "spec").map(|v| (v, "spec")),
        "deployment"
        | "daemonset"
        | "statefulset"
        | "replicaset"
        | "job"
        | "replicationcontroller" => get_value(obj, "spec")
            .and_then(|v| get_value(v, "template"))
            .and_then(|v| get_value(v, "spec"))
            .map(|v| (v, "spec.template.spec")),
        "cronjob" => get_value(obj, "spec")
            .and_then(|v| get_value(v, "jobTemplate"))
            .and_then(|v| get_value(v, "spec"))
            .and_then(|v| get_value(v, "template"))
            .and_then(|v| get_value(v, "spec"))
            .map(|v| (v, "spec.jobTemplate.spec.template.spec")),
        _ => None,
    }
}

fn audit_pod_spec(
    file: &Path,
    object: &str,
    pod_spec: &serde_yaml::Value,
    spec_path: &str,
    findings: &mut Vec<ContainerAuditFinding>,
    errors: &mut Vec<String>,
) {
    if get_bool(pod_spec, "hostNetwork") == Some(true) {
        push_finding(
            findings,
            file,
            object,
            "high",
            "host-network",
            "hostNetwork=true exposes host namespace to container network traffic",
            format!("{spec_path}.hostNetwork"),
        );
    }
    if get_bool(pod_spec, "hostPID") == Some(true) {
        push_finding(
            findings,
            file,
            object,
            "high",
            "host-pid",
            "hostPID=true allows process namespace visibility on the node",
            format!("{spec_path}.hostPID"),
        );
    }
    if get_bool(pod_spec, "hostIPC") == Some(true) {
        push_finding(
            findings,
            file,
            object,
            "medium",
            "host-ipc",
            "hostIPC=true shares host IPC namespace",
            format!("{spec_path}.hostIPC"),
        );
    }

    if let Some(pod_sc) = get_value(pod_spec, "securityContext") {
        if get_bool(pod_sc, "runAsNonRoot") == Some(false) {
            push_finding(
                findings,
                file,
                object,
                "medium",
                "run-as-root",
                "pod securityContext.runAsNonRoot=false",
                format!("{spec_path}.securityContext.runAsNonRoot"),
            );
        }
        if let Some(seccomp) = get_value(pod_sc, "seccompProfile")
            && get_str(seccomp, "type")
                .map(|s| s.eq_ignore_ascii_case("unconfined"))
                .unwrap_or(false)
        {
            push_finding(
                findings,
                file,
                object,
                "high",
                "seccomp-unconfined",
                "seccompProfile.type=Unconfined disables syscall sandboxing",
                format!("{spec_path}.securityContext.seccompProfile.type"),
            );
        }
    }

    if let Some(volumes) = get_value(pod_spec, "volumes").and_then(|v| v.as_sequence()) {
        for (idx, v) in volumes.iter().enumerate() {
            if let Some(host_path) = get_value(v, "hostPath") {
                let host_path_value = get_str(host_path, "path").unwrap_or("<unknown>");
                push_finding(
                    findings,
                    file,
                    object,
                    "high",
                    "hostpath-volume",
                    &format!("hostPath volume maps node path '{}'", host_path_value),
                    format!("{spec_path}.volumes[{idx}].hostPath"),
                );
            }
        }
    }

    for key in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(containers) = get_value(pod_spec, key).and_then(|v| v.as_sequence()) {
            for (idx, c) in containers.iter().enumerate() {
                let c_name = get_str(c, "name").unwrap_or("<unnamed>");
                let c_path = format!("{spec_path}.{key}[{idx}]");
                audit_container_security_context(file, object, c_name, c, &c_path, findings);
            }
        } else if get_value(pod_spec, key).is_some() {
            errors.push(format!(
                "{} {}: {} is not an array",
                file.display(),
                object,
                key
            ));
        }
    }
}

fn audit_container_security_context(
    file: &Path,
    object: &str,
    container_name: &str,
    container: &serde_yaml::Value,
    container_path: &str,
    findings: &mut Vec<ContainerAuditFinding>,
) {
    if let Some(sc) = get_value(container, "securityContext") {
        if get_bool(sc, "privileged") == Some(true) {
            push_finding(
                findings,
                file,
                object,
                "high",
                "privileged-container",
                &format!("container '{}' runs with privileged=true", container_name),
                format!("{container_path}.securityContext.privileged"),
            );
        }
        if get_bool(sc, "allowPrivilegeEscalation") == Some(true) {
            push_finding(
                findings,
                file,
                object,
                "high",
                "allow-privilege-escalation",
                &format!(
                    "container '{}' sets allowPrivilegeEscalation=true",
                    container_name
                ),
                format!("{container_path}.securityContext.allowPrivilegeEscalation"),
            );
        }
        if get_u64(sc, "runAsUser") == Some(0) {
            push_finding(
                findings,
                file,
                object,
                "medium",
                "run-as-root",
                &format!("container '{}' runs as UID 0", container_name),
                format!("{container_path}.securityContext.runAsUser"),
            );
        }
        if get_bool(sc, "readOnlyRootFilesystem") == Some(false) {
            push_finding(
                findings,
                file,
                object,
                "medium",
                "mutable-rootfs",
                &format!(
                    "container '{}' has readOnlyRootFilesystem=false",
                    container_name
                ),
                format!("{container_path}.securityContext.readOnlyRootFilesystem"),
            );
        }
        if let Some(caps) = get_value(sc, "capabilities")
            && let Some(add_caps) = get_value(caps, "add").and_then(|v| v.as_sequence())
            && add_caps
                .iter()
                .any(|x| x.as_str().map(|s| s == "SYS_ADMIN").unwrap_or(false))
        {
            push_finding(
                findings,
                file,
                object,
                "high",
                "sys-admin-capability",
                &format!(
                    "container '{}' adds Linux capability SYS_ADMIN",
                    container_name
                ),
                format!("{container_path}.securityContext.capabilities.add"),
            );
        }
    }
}

fn object_label(obj: &serde_yaml::Value) -> String {
    let kind = get_str(obj, "kind").unwrap_or("Unknown");
    let name = get_value(obj, "metadata")
        .and_then(|v| get_str(v, "name"))
        .unwrap_or("<unnamed>");
    format!("{kind}/{name}")
}

fn push_finding(
    findings: &mut Vec<ContainerAuditFinding>,
    file: &Path,
    object: &str,
    severity: &str,
    rule: &str,
    message: &str,
    path: String,
) {
    findings.push(ContainerAuditFinding {
        file: file.to_path_buf(),
        object: object.to_string(),
        severity: severity.to_string(),
        rule: rule.to_string(),
        message: message.to_string(),
        path,
    });
}

fn get_value<'a>(v: &'a serde_yaml::Value, key: &str) -> Option<&'a serde_yaml::Value> {
    v.as_mapping().and_then(|m| m.get(key))
}

fn get_str<'a>(v: &'a serde_yaml::Value, key: &str) -> Option<&'a str> {
    get_value(v, key).and_then(|x| x.as_str())
}

fn get_bool(v: &serde_yaml::Value, key: &str) -> Option<bool> {
    get_value(v, key).and_then(|x| x.as_bool())
}

fn get_u64(v: &serde_yaml::Value, key: &str) -> Option<u64> {
    get_value(v, key).and_then(|x| x.as_u64())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::audit_container_manifests_from_path;

    #[test]
    fn audit_detects_common_manifest_risks() {
        let tmp = std::env::temp_dir().join(format!(
            "rscan_container_audit_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).expect("create temp dir");
        let manifest = tmp.join("deploy.yaml");
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: risky-app
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: host-root
          hostPath:
            path: /
      containers:
        - name: app
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            capabilities:
              add: ["SYS_ADMIN"]
"#;
        std::fs::write(&manifest, yaml).expect("write manifest");

        let report = audit_container_manifests_from_path(&tmp).expect("audit ok");
        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.objects_scanned, 1);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "host-network" && f.object == "Deployment/risky-app")
        );
        assert!(report.findings.iter().any(|f| f.rule == "hostpath-volume"));
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "privileged-container")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "allow-privilege-escalation")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule == "sys-admin-capability")
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
