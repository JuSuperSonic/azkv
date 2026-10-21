use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph};

use crate::app::{DeleteConfirm, Duplicate, Picker};

use super::editor::field_line;
use super::theme::{ACCENT, DIM, centered, selection_style};

pub(super) fn draw_picker(frame: &mut Frame, picker: &Picker) {
    let area = centered(frame.area());
    frame.render_widget(Clear, area);
    let height = area.height.saturating_sub(2) as usize;
    let visible = picker.visible();
    let offset = picker.selected.saturating_sub(height.saturating_sub(1));
    let items: Vec<ListItem> = visible
        .iter()
        .skip(offset)
        .take(height)
        .filter_map(|index| picker.items.get(*index))
        .map(|item| ListItem::new(item.clone()))
        .collect();
    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(picker.selected - offset));
    }
    let title = if picker.filtering {
        format!(" {} /{}_ ", picker.title, picker.filter)
    } else if picker.filter.is_empty() {
        format!(" {} ", picker.title)
    } else {
        format!(" {} [{}] ", picker.title, picker.filter)
    };
    let list = List::new(items)
        .block(Block::bordered().title(title).border_style(Style::new().fg(ACCENT)))
        .highlight_style(selection_style())
        .highlight_symbol("› ");
    frame.render_stateful_widget(list, area, &mut state);
}

pub(super) fn draw_duplicate(frame: &mut Frame, duplicate: &Duplicate) {
    let area = dialog(frame.area(), 70, 8);
    frame.render_widget(Clear, area);
    let window = (area.width.saturating_sub(12) as usize * 2).max(40);
    let lines = vec![
        Line::from(vec![
            Span::styled(format!("{:<9}", "from"), Style::new().fg(DIM)),
            Span::raw(duplicate.source.clone()),
        ]),
        field_line(&duplicate.name, true, window),
        Line::from(""),
        Line::from(Span::styled("enter duplicate · esc cancel", Style::new().fg(DIM))),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" duplicate secret ").border_style(Style::new().fg(ACCENT))),
        area,
    );
}

pub(super) fn draw_delete_confirm(frame: &mut Frame, confirm: &DeleteConfirm) {
    let area = dialog(frame.area(), 70, 9);
    frame.render_widget(Clear, area);
    let option = |label: &str, focused: bool| {
        if focused {
            Span::styled(format!(" {label} "), selection_style())
        } else {
            Span::styled(format!(" {label} "), Style::new().fg(DIM))
        }
    };
    let lines = vec![
        Line::from(vec![
            Span::raw("delete secret "),
            Span::styled(format!("'{}'", confirm.name), Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw("?"),
        ]),
        Line::from(Span::styled("are you sure? soft delete: recoverable until purge", Style::new().fg(DIM))),
        Line::from(""),
        Line::from(vec![Span::raw("  "), option("Yes", confirm.yes), Span::raw("    "), option("No", !confirm.yes)]),
        Line::from(Span::styled("←/→ select · enter confirm · esc cancel", Style::new().fg(DIM))),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" delete secret ").border_style(Style::new().fg(Color::Red))),
        area,
    );
}

fn dialog(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}
