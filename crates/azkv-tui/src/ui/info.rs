use ratatui::Frame;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::App;

use super::theme::{ACCENT, DIM, centered, spinner};

pub(super) fn draw_info(frame: &mut Frame, app: &App) {
    let area = centered(frame.area());
    frame.render_widget(Clear, area);
    let vault = app.info_vault();
    let name = vault.map(|vault| vault.name.as_str()).unwrap_or("-");
    let label_width = 14;
    let field = |label: &str, value: String| {
        Line::from(vec![Span::styled(format!("{label:<label_width$}"), Style::new().fg(DIM)), Span::raw(value)])
    };
    let mut lines = Vec::new();
    match &app.info {
        None => {
            lines.push(Line::from(Span::styled(format!("{} loading...", spinner()), Style::new().fg(Color::Yellow))))
        },
        Some(Err(err)) => lines.push(Line::from(Span::styled(err.clone(), Style::new().fg(Color::Red)))),
        Some(Ok(info)) => {
            let group = info
                .resource_group
                .as_deref()
                .or_else(|| vault.and_then(|vault| vault.resource_group.as_deref()))
                .unwrap_or("-");
            let firewall = match info.firewall.as_deref() {
                Some(action) => {
                    let mut text = action.to_string();
                    if !info.ip_rules.is_empty() {
                        text.push_str(&format!(" · {} IP", info.ip_rules.len()));
                    }
                    if info.vnet_rules > 0 {
                        text.push_str(&format!(" · {} VNet", info.vnet_rules));
                    }
                    if let Some(bypass) = &info.bypass {
                        text.push_str(&format!(" · bypass {bypass}"));
                    }
                    text
                },
                None => "-".into(),
            };
            let access = match info.rbac {
                Some(true) => "RBAC",
                Some(false) => "access policies",
                None => "-",
            };
            let roles = if info.roles.is_empty() { "-".to_string() } else { info.roles.join(", ") };
            lines.push(field("name", name.to_string()));
            lines.push(field("subscription", vault.map(|vault| vault.subscription_name.clone()).unwrap_or_default()));
            lines.push(field("resource", group.to_string()));
            lines.push(field("location", format!("{} · {}", dash(&info.location), dash(&info.sku))));
            lines.push(field("url", app.info_url.clone().unwrap_or_default()));
            lines.push(Line::from(""));
            lines.push(section("network"));
            lines.push(field("public", dash(&info.public_network_access)));
            lines.push(field("firewall", firewall));
            lines.push(field("private", format!("{} endpoint(s)", info.private_endpoints)));
            let client = match info.client_ip {
                Some(ip) => {
                    let (verdict, color) = ip_verdict(info.client_allowed, info.private_endpoints);
                    Line::from(vec![
                        Span::styled(format!("{:<label_width$}", "your ip"), Style::new().fg(DIM)),
                        Span::raw(ip.to_string()),
                        Span::styled(format!(" · {verdict}"), Style::new().fg(color)),
                    ])
                },
                None => field("your ip", "-".into()),
            };
            lines.push(client);
            lines.push(Line::from(""));
            lines.push(section("access"));
            let auth = {
                let mut spans = vec![
                    Span::styled(format!("{:<label_width$}", "auth"), Style::new().fg(DIM)),
                    Span::raw(access.to_string()),
                ];
                if info.rbac == Some(false) {
                    spans.push(Span::styled(
                        "  warning: deprecated",
                        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    ));
                }
                Line::from(spans)
            };
            lines.push(auth);
            lines.push(field("user", dash(&info.user)));
            if info.rbac == Some(true) {
                lines.push(field("roles", roles));
            }
            if let Some(err) = &info.roles_error {
                lines.push(Line::from(Span::styled(format!("roles unavailable: {err}"), Style::new().fg(Color::Red))));
            }
            lines.push(field(
                "soft delete",
                info.soft_delete_days.map(|days| format!("{days} days")).unwrap_or_else(|| "-".into()),
            ));
            lines.push(field(
                "purge",
                match info.purge_protection {
                    Some(true) => "protected",
                    Some(false) => "off",
                    None => "-",
                }
                .to_string(),
            ));
        },
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("↑/↓ vault · r refresh · esc close", Style::new().fg(DIM))));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(format!(" vault {name} ")).border_style(Style::new().fg(ACCENT))),
        area,
    );
}

/// A denied public address is not a dead end when the vault has a private endpoint.
fn ip_verdict(allowed: Option<bool>, private_endpoints: usize) -> (&'static str, Color) {
    match allowed {
        Some(true) => ("allowed", Color::Green),
        Some(false) if private_endpoints > 0 => ("public path denied", Color::Yellow),
        Some(false) => ("denied", Color::Red),
        None => ("unknown", DIM),
    }
}

fn dash(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "-".into())
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(title.to_string(), Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)))
}

#[cfg(test)]
mod tests {
    use super::ip_verdict;
    use ratatui::style::Color;

    #[test]
    fn private_endpoint_softens_a_denied_public_address() {
        assert_eq!(ip_verdict(Some(true), 0), ("allowed", Color::Green));
        assert_eq!(ip_verdict(Some(false), 0), ("denied", Color::Red));
        assert_eq!(ip_verdict(Some(false), 1), ("public path denied", Color::Yellow));
        assert_eq!(ip_verdict(None, 1).0, "unknown");
    }
}
