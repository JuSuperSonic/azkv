use ratatui::Frame;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::app::{EditField, Editor, ProxyEditor};

use super::theme::{ACCENT, DIM, centered, selection_style};

pub(super) fn draw_editor(frame: &mut Frame, editor: &Editor) {
    let area = centered(frame.area());
    frame.render_widget(Clear, area);
    let mut lines: Vec<Line> = Vec::new();
    let offset = usize::from(editor.name.is_some());
    let window = (area.width.saturating_sub(12) as usize * 2).max(40);
    if let Some(name) = &editor.name {
        lines.push(field_line(name, editor.active == 0, window));
    }
    lines.extend(
        editor
            .fields
            .iter()
            .enumerate()
            .map(|(index, field)| field_line(field, index + offset == editor.active, window)),
    );
    let enabled_active = editor.active == editor.fields.len() + offset;
    lines.push(Line::from(vec![
        Span::styled(format!("{:<9}", "enabled"), Style::new().fg(if enabled_active { ACCENT } else { DIM })),
        Span::styled(
            if editor.enabled { "[x] on" } else { "[ ] off" },
            if enabled_active {
                selection_style()
            } else if editor.enabled {
                Style::new().fg(Color::Green)
            } else {
                Style::new().fg(DIM)
            },
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "tab/↑↓ field · space toggle · ctrl+a/e start/end · enter save · esc cancel",
        Style::new().fg(DIM),
    )));
    lines.push(Line::from(Span::styled("value: shift+enter or ctrl+j newline · ctrl+v paste", Style::new().fg(DIM))));
    lines.push(Line::from(Span::styled(
        "tags key=value, key=value · expires/activates YYYY-MM-DD",
        Style::new().fg(DIM),
    )));
    let title = if editor.name.is_some() { " new secret ".to_string() } else { format!(" edit {} ", editor.secret) };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(title).border_style(Style::new().fg(ACCENT))),
        area,
    );
}

pub(super) fn draw_proxy_editor(frame: &mut Frame, editor: &ProxyEditor) {
    let area = centered(frame.area());
    frame.render_widget(Clear, area);
    let window = (area.width.saturating_sub(12) as usize * 2).max(40);
    let toggle_style = if editor.active == 0 {
        selection_style()
    } else if editor.enabled {
        Style::new().fg(Color::Green)
    } else {
        Style::new().fg(DIM)
    };
    let scheme_style = if editor.active == 1 { selection_style() } else { Style::new().fg(Color::White) };
    let lines = vec![
        Line::from(vec![
            Span::styled(format!("{:<9}", "enabled"), Style::new().fg(if editor.active == 0 { ACCENT } else { DIM })),
            Span::styled(if editor.enabled { "[x] on" } else { "[ ] off" }, toggle_style),
        ]),
        Line::from(vec![
            Span::styled(format!("{:<9}", "scheme"), Style::new().fg(if editor.active == 1 { ACCENT } else { DIM })),
            Span::styled(if editor.scheme == 1 { "socks5h" } else { "http" }, scheme_style),
        ]),
        field_line(&editor.host, editor.active == 2, window),
        field_line(&editor.port, editor.active == 3, window),
        Line::from(""),
        Line::from(Span::styled(
            "space toggle · ←/→ scheme · tab/↑↓ fields · enter apply · esc cancel",
            Style::new().fg(DIM),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" proxy (Key Vault only) ").border_style(Style::new().fg(ACCENT))),
        area,
    );
}

pub(super) fn field_line(field: &EditField, active: bool, window: usize) -> Line<'static> {
    let label = Style::new().fg(if active { ACCENT } else { DIM });
    let display: Vec<char> = field.display().chars().collect();
    let mut spans = vec![Span::styled(format!("{:<9}", field.label), label)];
    let cursor = field.cursor().min(display.len());
    let (start, end) = value_window(display.len(), cursor, window);
    if start > 0 {
        spans.push(Span::styled("…", Style::new().fg(DIM)));
    }
    if active {
        if field.is_selected() && !display.is_empty() {
            // Fresh focus: highlight the whole value so typing replaces it.
            spans.push(Span::styled(display[start..end].iter().collect::<String>(), selection_style()));
        } else {
            // Cursor as a solid block, like a single-line input.
            let before: String = display[start..cursor].iter().collect();
            let at = display.get(cursor).copied().unwrap_or(' ');
            let after: String = display[(cursor + 1).min(end)..end].iter().collect();
            spans.push(Span::raw(before));
            spans.push(Span::styled(at.to_string(), selection_style()));
            spans.push(Span::raw(after));
        }
    } else {
        spans.push(Span::raw(display[start..end].iter().collect::<String>()));
    }
    if end < display.len() {
        spans.push(Span::styled("…", Style::new().fg(DIM)));
    }
    Line::from(spans)
}

/// Visible slice of a value around the cursor, so long/multiline secrets do
/// not push the other editor fields off screen.
fn value_window(len: usize, cursor: usize, window: usize) -> (usize, usize) {
    if len <= window {
        return (0, len);
    }
    let start = cursor.saturating_sub(window / 2).min(len - window);
    (start, start + window)
}

#[cfg(test)]
mod tests {
    use super::value_window;

    #[test]
    fn value_window_follows_the_cursor() {
        assert_eq!(value_window(10, 5, 40), (0, 10));
        assert_eq!(value_window(100, 0, 40), (0, 40));
        assert_eq!(value_window(100, 50, 40), (30, 70));
        assert_eq!(value_window(100, 100, 40), (60, 100));
    }
}
