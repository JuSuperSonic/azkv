use azkv_core::Vault;
use azkv_core::copy::{CopyPlan, CopyReport};

pub fn render_plan(source: &Vault, dest: &Vault, plan: &CopyPlan) -> Vec<String> {
    let mut lines = vec![
        format!("source:      {} ({})", source.url, source.subscription_name),
        format!("destination: {} ({})", dest.url, dest.subscription_name),
        format!(
            "plan: {} to create, {} to overwrite, {} already exist",
            plan.create.len(),
            plan.overwrite.len(),
            plan.conflicts()
        ),
    ];
    for name in &plan.skip {
        lines.push(format!("  WARN  {name} already exists in destination (skipped, use --overwrite)"));
    }
    lines
}

pub fn render_report(report: &CopyReport) -> Vec<String> {
    let mut lines = Vec::new();
    for name in &report.created {
        lines.push(format!("  OK      {name}"));
    }
    for name in &report.overwritten {
        lines.push(format!("  UPDATE  {name}"));
    }
    for name in &report.skipped {
        lines.push(format!("  SKIP    {name} (already exists)"));
    }
    for (name, error) in &report.failed {
        lines.push(format!("  FAIL    {name}: {error}"));
    }
    lines.push(format!(
        "summary: {} created, {} overwritten, {} skipped (already exist), {} failed",
        report.created.len(),
        report.overwritten.len(),
        report.skipped.len(),
        report.failed.len()
    ));
    lines
}

#[cfg(test)]
mod tests {
    fn vault(name: &str) -> Vault {
        Vault {
            name: name.into(),
            url: azkv_core::model::url_for(name),
            subscription_id: "s1".into(),
            subscription_name: "sub-one".into(),
            tenant_id: "t1".into(),
            resource_group: None,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    use std::collections::BTreeSet;

    use azkv_core::copy::{CopyReport, plan};

    use super::*;

    #[test]
    fn plan_alerts_on_existing_secrets() {
        let existing = BTreeSet::from(["old".to_string()]);
        let plan = plan(&strings(&["new", "old"]), &existing, false);
        let lines = render_plan(&vault("kv-a"), &vault("kv-b"), &plan);
        assert!(lines[0].contains("kv-a.vault.azure.net"));
        assert!(lines[1].contains("kv-b.vault.azure.net"));
        assert!(lines[2].contains("1 to create, 0 to overwrite, 1 already exist"));
        assert!(lines[3].contains("WARN  old already exists"));
    }

    #[test]
    fn report_lines_cover_every_outcome() {
        let report = CopyReport {
            created: strings(&["a"]),
            overwritten: strings(&["b"]),
            skipped: strings(&["c"]),
            failed: vec![("d".into(), "denied".into())],
        };
        let lines = render_report(&report);
        assert!(lines[0].contains("OK      a"));
        assert!(lines[1].contains("UPDATE  b"));
        assert!(lines[2].contains("SKIP    c (already exists)"));
        assert!(lines[3].contains("FAIL    d: denied"));
        assert_eq!(lines[4], "summary: 1 created, 1 overwritten, 1 skipped (already exist), 1 failed");
    }

    #[test]
    fn successful_report_has_no_failures() {
        let report = CopyReport { created: strings(&["a"]), ..Default::default() };
        assert!(report.succeeded());
        assert!(render_report(&report)[1].starts_with("summary: 1 created"));
    }
}
