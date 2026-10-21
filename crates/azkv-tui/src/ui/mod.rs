//! TUI rendering, split by surface: panes, dialogs, editors and the info window.

mod dialogs;
mod editor;
mod info;
mod panes;
mod theme;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};

use crate::app::App;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let footer = if app.show_hints { panes::footer_height(app, frame.area().width) } else { 1 };
    let areas =
        Layout::vertical([Constraint::Length(1), Constraint::Min(3), Constraint::Length(footer)]).split(frame.area());

    panes::draw_header(frame, app, areas[0]);
    let columns =
        Layout::horizontal([Constraint::Length(32), Constraint::Min(30), Constraint::Length(30)]).split(areas[1]);
    panes::draw_vaults(frame, app, columns[0]);
    panes::draw_secrets(frame, app, columns[1]);
    panes::draw_details(frame, app, columns[2]);
    panes::draw_footer(frame, app, areas[2]);

    if let Some(picker) = &app.picker {
        dialogs::draw_picker(frame, picker);
    }
    if let Some(editor) = &app.editor {
        editor::draw_editor(frame, editor);
    }
    if let Some(editor) = &app.proxy_editor {
        editor::draw_proxy_editor(frame, editor);
    }
    if app.info_url.is_some() {
        info::draw_info(frame, app);
    }
    if let Some(duplicate) = &app.duplicate {
        dialogs::draw_duplicate(frame, duplicate);
    }
    if let Some(confirm) = &app.confirm_delete {
        dialogs::draw_delete_confirm(frame, confirm);
    }
}
