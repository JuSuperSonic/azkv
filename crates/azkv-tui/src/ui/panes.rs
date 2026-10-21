use azkv_core::fmt_timestamp;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, List, ListItem, Paragraph, Row, Table, Wrap};

use crate::app::{App, Pane, PickerKind};

use super::theme::{ACCENT, DIM, pane, selection_style, spinner, state_style};

pub(super) fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(" azkv ", Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
    ];
    if let Some(profile) = app.profile() {
        spans.push(Span::styled(profile.name.clone(), Style::new().fg(Color::Yellow)));
    }
    let tenant = app
        .tenant_idx
        .and_then(|index| app.tenants.get(index))
        .map(|tenant| tenant.name.clone())
        .unwrap_or_else(|| "all tenants".into());
    spans.push(Span::styled(format!("  {tenant}  "), Style::new().fg(DIM)));
    if let Some(sub) = app.subscription() {
        spans.push(Span::styled(format!("{} ", sub.name), Style::new().fg(Color::White)));
    }
    if let Some(vault) = app.vault() {
        spans.push(Span::styled(format!("· {} ", vault.name), Style::new().fg(ACCENT)));
    }
    if app.proxy.is_some() {
        spans.push(Span::styled("· proxy ", Style::new().fg(Color::Magenta)));
    }
    if app.loading {
        spans.push(Span::styled(format!("{} loading...", spinner()), Style::new().fg(Color::Yellow)));
    } else {
        spans.push(Span::styled(format!("{} secrets", app.secrets.len()), Style::new().fg(DIM)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

pub(super) fn draw_vaults(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .visible_vaults()
        .into_iter()
        .filter_map(|index| app.vaults.get(index))
        .map(|vault| ListItem::new(vault.name.clone()))
        .collect();
    let title = if app.vault_filter.is_empty() {
        format!(" vaults ({}) ", items.len())
    } else {
        format!(" vaults [{}] ", app.vault_filter)
    };
    let focused = app.pane == Pane::Vaults;
    let list = List::new(items).block(pane(title, focused)).highlight_style(selection_style()).highlight_symbol("› ");
    frame.render_stateful_widget(list, area, &mut app.vault_state);
}

pub(super) fn draw_secrets(frame: &mut Frame, app: &mut App, area: Rect) {
    let rows: Vec<Row> = app
        .visible_secrets()
        .into_iter()
        .filter_map(|index| app.secrets.get(index))
        .map(|secret| {
            let state = secret.current_state();
            let updated = fmt_timestamp(secret.updated)
                .and_then(|date| date.get(..10).map(str::to_string))
                .unwrap_or_else(|| "-".into());
            Row::new(vec![
                Cell::from(secret.name.clone()),
                Cell::from(Line::from(state.label()).alignment(Alignment::Center)).style(state_style(state)),
                Cell::from(Line::from(if secret.enabled { "yes" } else { "no" }).alignment(Alignment::Center))
                    .style(if secret.enabled { Style::new().fg(Color::Green) } else { Style::new().fg(DIM) }),
                Cell::from(Line::from(updated).alignment(Alignment::Center)),
            ])
        })
        .collect();
    let title = if app.filtering && app.pane == Pane::Secrets {
        format!(" secrets /{}_ ", app.secret_filter)
    } else if app.secret_filter.is_empty() {
        format!(" secrets ({}) ", rows.len())
    } else {
        format!(" secrets [{}] ", app.secret_filter)
    };
    let focused = app.pane == Pane::Secrets;
    let widths = [
        Constraint::Min(10),
        Constraint::Length(8),
        Constraint::Length(9),
        // Two spare columns keep the centered date off the right border.
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new([
                Line::from("NAME"),
                Line::from("STATUS").alignment(Alignment::Center),
                Line::from("ENABLED").alignment(Alignment::Center),
                Line::from("UPDATED").alignment(Alignment::Center),
            ])
            .style(Style::new().fg(DIM).add_modifier(Modifier::BOLD)),
        )
        .block(pane(title, focused))
        .row_highlight_style(selection_style())
        .highlight_symbol("› ");
    frame.render_stateful_widget(table, area, &mut app.secret_state);
}

pub(super) fn draw_details(frame: &mut Frame, app: &App, area: Rect) {
    let Some(secret) = app.selected_secret() else {
        frame.render_widget(
            Paragraph::new("select a secret").style(Style::new().fg(DIM)).block(pane("details".into(), false)),
            area,
        );
        return;
    };

    let mut lines = vec![
        field("name", secret.name.clone()),
        field("state", secret.current_state().label().to_string()),
        field("enabled", if secret.enabled { "yes" } else { "no" }),
        field("updated", fmt_timestamp(secret.updated).unwrap_or_else(|| "-".into())),
        field("expires", fmt_timestamp(secret.expires).unwrap_or_else(|| "-".into())),
        field("activates", fmt_timestamp(secret.not_before).unwrap_or_else(|| "-".into())),
        field("type", secret.content_type.clone().unwrap_or_else(|| "-".into())),
    ];
    if !secret.tags.is_empty() {
        let tags = secret.tags.iter().map(|(key, value)| format!("{key}={value}")).collect::<Vec<_>>().join(" ");
        lines.push(field("tags", tags));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("value", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))));

    match app.values.get(&secret.name) {
        Some(Ok(value)) if app.revealed => {
            for line in value.lines() {
                lines.push(Line::from(line.to_string()));
            }
            if value.is_empty() {
                lines.push(Line::from(Span::styled("(empty)", Style::new().fg(DIM))));
            }
        },
        Some(Ok(value)) => {
            let length = value.chars().count();
            lines.push(Line::from(Span::styled("•".repeat(length.min(40)), Style::new().fg(DIM))));
            lines.push(Line::from(Span::styled(
                format!("{length} chars - space to reveal, c to copy"),
                Style::new().fg(DIM),
            )));
        },
        Some(Err(err)) => lines.push(Line::from(Span::styled(err.clone(), Style::new().fg(Color::Red)))),
        None => {
            lines.push(Line::from(Span::styled(format!("{} loading...", spinner()), Style::new().fg(Color::Yellow))))
        },
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(pane("details".into(), false)), area);
}

pub(super) fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let status_style = if status_is_error(&app.status) {
        Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if app.confirm_overwrite.is_some() {
        Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(DIM)
    };
    if !app.show_hints {
        frame.render_widget(Paragraph::new(Span::styled(app.status.clone(), status_style)), area);
        return;
    }
    let hints = if app.info_url.is_some() {
        info_hints()
    } else if let Some(picker) = &app.picker {
        picker_hints(picker.kind)
    } else if app.filtering {
        vec![("type", "filter"), ("enter", "keep"), ("esc", "clear")]
    } else {
        hints_for(app.pane)
    };
    let mut spans = Vec::new();
    for (key, label) in hints {
        spans.push(Span::styled(format!(" {key} "), Style::new().fg(ACCENT)));
        spans.push(Span::styled(format!("{label} "), Style::new().fg(DIM)));
    }
    let lines = vec![Line::from(spans), Line::from(Span::styled(app.status.clone(), status_style))];
    frame.render_widget(Paragraph::new(lines), area);
}

/// Footer hints while a picker is open. Only the copy-vault list can reload.
fn picker_hints(kind: PickerKind) -> Vec<(&'static str, &'static str)> {
    let mut hints = vec![("↑/↓", "select"), ("enter", "confirm"), ("esc", "cancel")];
    if kind == PickerKind::CopyVault {
        hints.insert(2, ("r", "refresh"));
    }
    hints
}

/// Footer hints while the vault info window is open; pane keys are unusable.
fn info_hints() -> Vec<(&'static str, &'static str)> {
    vec![("↑/↓", "vault"), ("r", "refresh"), ("esc", "close")]
}

/// Footer hints for the focused pane; global keys stay in both lists.
fn hints_for(pane: Pane) -> Vec<(&'static str, &'static str)> {
    let nav = [("↑/↓", "move"), ("g/G", "top/bottom"), ("tab/←→", "pane")];
    let rest = [("/", "filter"), ("P", "proxy"), ("r", "refresh"), ("q", "quit")];
    let pane_specific: &[(&'static str, &'static str)] = match pane {
        Pane::Vaults => &[
            ("enter", "secrets"),
            ("i", "info"),
            ("C", "copy all"),
            ("p", "profile"),
            ("t", "tenant"),
            ("s", "subscription"),
        ],
        Pane::Secrets => &[
            ("space", "reveal"),
            ("e", "edit"),
            ("a", "new"),
            ("d", "duplicate"),
            ("D", "delete"),
            ("c", "copy"),
            ("y", "name"),
            ("C", "→vault"),
        ],
    };
    nav.iter().chain(pane_specific.iter()).chain(rest.iter()).copied().collect()
}

/// Status messages that must stand out from normal progress text.
fn status_is_error(status: &str) -> bool {
    let status = status.to_ascii_lowercase();
    status.starts_with("error:")
        || status.starts_with("save failed")
        || status.starts_with("delete failed")
        || status.starts_with("duplicate failed")
        || status.starts_with("copy failed")
        || status.starts_with("clipboard error")
        || status.starts_with("proxy: address")
        || status.starts_with("proxy: invalid")
        || status.starts_with("expires:")
        || status.starts_with("tags:")
}

fn field(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![Span::styled(format!("{label:<10}"), Style::new().fg(DIM)), Span::raw(value.into())])
}

#[cfg(test)]
mod tests {
    use super::{hints_for, info_hints, picker_hints, status_is_error};
    use crate::app::{Pane, PickerKind};

    #[test]
    fn footer_hints_follow_the_focused_pane() {
        let vaults = hints_for(Pane::Vaults);
        assert!(vaults.contains(&("enter", "secrets")));
        assert!(vaults.contains(&("g/G", "top/bottom")));
        assert!(vaults.contains(&("p", "profile")));
        assert!(vaults.contains(&("C", "copy all")));
        assert!(!vaults.iter().any(|(_, label)| *label == "delete"));

        let secrets = hints_for(Pane::Secrets);
        assert!(secrets.contains(&("d", "duplicate")));
        assert!(secrets.contains(&("D", "delete")));
        assert!(secrets.contains(&("a", "new")));
        assert!(secrets.contains(&("space", "reveal")));
        assert!(secrets.contains(&("g/G", "top/bottom")));
        assert!(!secrets.iter().any(|(key, _)| *key == "enter"));
        assert!(!secrets.iter().any(|(_, label)| *label == "info"));

        assert!(secrets.contains(&("P", "proxy")));
        assert!(vaults.contains(&("P", "proxy")));
    }

    #[test]
    fn copy_vault_picker_has_refresh_hint() {
        let hints = picker_hints(PickerKind::CopyVault);
        assert!(hints.contains(&("r", "refresh")));
        assert!(!picker_hints(PickerKind::Subscriptions).iter().any(|(key, _)| *key == "r"));
    }

    #[test]
    fn info_hints_hide_unusable_pane_keys() {
        let hints = info_hints();
        assert!(hints.contains(&("↑/↓", "vault")));
        assert!(hints.contains(&("r", "refresh")));
        assert!(hints.contains(&("esc", "close")));
        assert!(!hints.iter().any(|(_, label)| *label == "proxy"));
        assert!(!hints.iter().any(|(_, label)| *label == "secrets"));
    }

    #[test]
    fn error_statuses_are_recognised() {
        assert!(status_is_error("error: cannot reach https://example"));
        assert!(status_is_error("save failed: denied"));
        assert!(status_is_error("delete failed: denied"));
        assert!(status_is_error("duplicate failed: already exists"));
        assert!(status_is_error("copy failed: 2 of 5 secrets"));
        assert!(status_is_error("clipboard error: no display"));
        assert!(status_is_error("proxy: address required"));
        assert!(status_is_error("proxy: invalid proxy URL"));
        assert!(status_is_error("expires: expected YYYY-MM-DD"));
        assert!(status_is_error("tags: 'bad' is not key=value"));
    }

    #[test]
    fn normal_statuses_stay_dim() {
        assert!(!status_is_error("42 secrets"));
        assert!(!status_is_error("proxy: space toggle, left/right scheme"));
        assert!(!status_is_error("copied to clipboard"));
    }
}
