use ratatui::crossterm::event::KeyCode;
use time::OffsetDateTime;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FieldKind {
    Text,
    Date,
}

#[derive(Clone)]
pub struct EditField {
    pub label: &'static str,
    pub(super) value: Vec<char>,
    pub(super) cursor: usize,
    pub(super) dirty: bool,
    pub(super) selected: bool,
    kind: FieldKind,
}

impl EditField {
    pub(super) fn new(label: &'static str, text: &str) -> Self {
        Self::with_kind(label, text, FieldKind::Text)
    }

    pub(super) fn date(label: &'static str, text: &str) -> Self {
        Self::with_kind(label, text, FieldKind::Date)
    }

    fn with_kind(label: &'static str, text: &str, kind: FieldKind) -> Self {
        let value: Vec<char> = text.chars().collect();
        Self { label, cursor: value.len(), value, dirty: false, selected: false, kind }
    }

    pub fn placeholder(&self) -> Option<&'static str> {
        (self.kind == FieldKind::Date && self.value.is_empty()).then_some("____-__-__")
    }

    pub fn display(&self) -> String {
        self.value
            .iter()
            .map(|character| match character {
                '\n' => '⏎',
                '\r' => ' ',
                other => *other,
            })
            .collect()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn is_selected(&self) -> bool {
        self.selected
    }

    pub(super) fn focus(&mut self) {
        self.cursor = self.value.len();
        self.selected = true;
    }

    pub(super) fn deselect(&mut self) {
        self.selected = false;
    }

    pub(super) fn text(&self) -> String {
        self.value.iter().collect()
    }

    pub(super) fn insert(&mut self, character: char) {
        if self.kind == FieldKind::Date {
            if character.is_ascii_digit() {
                if self.selected {
                    self.value.clear();
                    self.cursor = 0;
                    self.selected = false;
                }
                self.insert_date_digit(character);
            }
            return;
        }
        if self.selected {
            self.replace(character);
            return;
        }
        self.value.insert(self.cursor, character);
        self.cursor += 1;
        self.dirty = true;
    }

    /// Inserts pasted text as-is, replacing a selected value first.
    pub(super) fn insert_text(&mut self, text: &str) {
        if self.kind == FieldKind::Date {
            let pasted: Vec<char> = text.chars().filter(|character| character.is_ascii_digit()).collect();
            if pasted.is_empty() {
                return;
            }
            if self.selected {
                self.value.clear();
                self.cursor = 0;
                self.selected = false;
            }
            let mut digits = self.date_digits();
            let start = self.digit_index();
            let room = 8usize.saturating_sub(digits.len());
            for (offset, character) in pasted.into_iter().take(room).enumerate() {
                digits.insert(start + offset, character);
            }
            self.set_date_digits(&digits);
            return;
        }
        if self.selected {
            self.value.clear();
            self.cursor = 0;
            self.selected = false;
        }
        let count = text.chars().count();
        self.value.splice(self.cursor..self.cursor, text.chars());
        self.cursor += count;
        self.dirty = true;
    }

    pub(super) fn replace(&mut self, character: char) {
        self.value.clear();
        self.value.push(character);
        self.cursor = 1;
        self.selected = false;
        self.dirty = true;
    }

    pub(super) fn backspace(&mut self) {
        if self.kind == FieldKind::Date {
            if self.selected {
                self.value.clear();
                self.cursor = 0;
                self.selected = false;
                self.dirty = true;
                return;
            }
            let at = self.digit_index();
            if at == 0 {
                return;
            }
            let mut digits = self.date_digits();
            digits.remove(at - 1);
            self.set_date_digits(&digits);
            return;
        }
        if self.selected {
            self.value.clear();
            self.cursor = 0;
            self.selected = false;
            self.dirty = true;
        } else if self.cursor > 0 {
            self.cursor -= 1;
            self.value.remove(self.cursor);
            self.dirty = true;
        }
    }

    pub(super) fn delete(&mut self) {
        if self.kind == FieldKind::Date {
            if self.selected {
                self.value.clear();
                self.cursor = 0;
                self.selected = false;
                self.dirty = true;
                return;
            }
            let at = self.digit_index();
            let mut digits = self.date_digits();
            if at >= digits.len() {
                return;
            }
            digits.remove(at);
            self.set_date_digits(&digits);
            return;
        }
        if self.selected {
            self.value.clear();
            self.cursor = 0;
            self.selected = false;
            self.dirty = true;
        } else if self.cursor < self.value.len() {
            self.value.remove(self.cursor);
            self.dirty = true;
        }
    }

    pub(super) fn date_digits(&self) -> Vec<char> {
        self.value.iter().copied().filter(|character| character.is_ascii_digit()).collect()
    }

    /// Number of digits before the cursor, i.e. the insert position.
    pub(super) fn digit_index(&self) -> usize {
        self.value[..self.cursor.min(self.value.len())].iter().filter(|character| character.is_ascii_digit()).count()
    }

    pub(super) fn insert_date_digit(&mut self, character: char) {
        let mut digits = self.date_digits();
        if digits.len() == 8 {
            return;
        }
        let at = self.digit_index();
        digits.insert(at, character);
        self.set_date_digits(&digits);
    }

    /// Rewrites `digits` as `YYYY-MM-DD` with dashes after the 4th and 6th digit.
    pub(super) fn set_date_digits(&mut self, digits: &[char]) {
        let mut text = String::new();
        for (index, digit) in digits.iter().enumerate() {
            if index == 4 || index == 6 {
                text.push('-');
            }
            text.push(*digit);
        }
        self.value = text.chars().collect();
        let position = digits.len();
        self.cursor = position + usize::from(position > 4) + usize::from(position > 6);
        self.dirty = true;
    }
}

#[derive(Clone)]
pub struct Editor {
    pub secret: String,
    /// Set only when creating a secret; the name is then the first field.
    pub name: Option<EditField>,
    pub fields: Vec<EditField>,
    /// Checkbox after the text fields; `space` toggles it.
    pub enabled: bool,
    pub active: usize,
    /// True for a disabled secret: its value cannot be read or edited until enabled.
    pub value_locked: bool,
    pub(super) original_value: String,
    pub(super) original_expires: Option<OffsetDateTime>,
    pub(super) original_not_before: Option<OffsetDateTime>,
    pub(super) original_updated: Option<i128>,
}

impl Editor {
    pub(super) fn field(&self, index: usize) -> &EditField {
        &self.fields[index]
    }

    pub(super) fn field_count(&self) -> usize {
        self.fields.len() + usize::from(self.name.is_some()) + 1
    }

    pub(super) fn active_field_mut(&mut self) -> Option<&mut EditField> {
        let offset = usize::from(self.name.is_some());
        if self.name.is_some() && self.active == 0 {
            self.name.as_mut()
        } else {
            self.fields.get_mut(self.active.checked_sub(offset)?)
        }
    }

    /// Untouched values keep their original text, including newlines.
    pub(super) fn value_for_save(&self) -> String {
        if self.fields[0].dirty { self.fields[0].text() } else { self.original_value.clone() }
    }
}

pub(super) fn edit_field(field: &mut EditField, code: KeyCode) {
    match code {
        KeyCode::Left => {
            field.deselect();
            field.cursor = field.cursor.saturating_sub(1);
        },
        KeyCode::Right => {
            field.deselect();
            field.cursor = (field.cursor + 1).min(field.value.len());
        },
        KeyCode::Home => {
            field.deselect();
            field.cursor = 0;
        },
        KeyCode::End => {
            field.deselect();
            field.cursor = field.value.len();
        },
        KeyCode::Backspace => field.backspace(),
        KeyCode::Delete => field.delete(),
        KeyCode::Char(character) if !character.is_control() => field.insert(character),
        _ => {},
    }
}
