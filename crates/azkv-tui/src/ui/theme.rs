use std::time::{SystemTime, UNIX_EPOCH};

use azkv_core::SecretState;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Block;

pub(super) const ACCENT: Color = Color::Cyan;
pub(super) const DIM: Color = Color::DarkGray;

/// Animated marker for the event loop's loading redraws.
pub(super) fn spinner() -> &'static str {
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let millis = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    FRAMES[(millis / 100) as usize % FRAMES.len()]
}

pub(super) fn centered(area: Rect) -> Rect {
    let width = (area.width as f32 * 0.6).clamp(20.0, 90.0) as u16;
    let height = (area.height as f32 * 0.6).max(6.0) as u16;
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

pub(super) fn pane(title: String, focused: bool) -> Block<'static> {
    Block::bordered().title(title).border_style(border_style(focused))
}

fn border_style(focused: bool) -> Style {
    if focused { Style::new().fg(ACCENT) } else { Style::new().fg(DIM) }
}

pub(super) fn selection_style() -> Style {
    Style::new().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)
}

pub(super) fn state_style(state: SecretState) -> Style {
    match state {
        SecretState::On => Style::new().fg(Color::Green),
        SecretState::Off => Style::new().fg(DIM),
        SecretState::Expired => Style::new().fg(Color::Red),
        SecretState::Pending => Style::new().fg(Color::Yellow),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_state_is_highlighted() {
        assert_eq!(state_style(SecretState::Pending), Style::new().fg(Color::Yellow));
    }
}
