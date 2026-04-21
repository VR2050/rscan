use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::tui::reverse_workbench_support::relative_or_full;

use super::{PickerInputMode, PickerLauncherMode, PickerRootMode, ReversePickerState};

pub(super) fn draw_picker(f: &mut Frame<'_>, state: &ReversePickerState) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(8),
            Constraint::Length(8),
        ])
        .split(f.size());
    draw_header(f, areas[0], state);
    draw_entries(f, areas[1], state);
    draw_footer(f, areas[2], state);
}

fn draw_header(f: &mut Frame<'_>, area: Rect, state: &ReversePickerState) {
    let mode = match state.input_mode {
        PickerInputMode::Browse => "browse",
        PickerInputMode::Filter => "filter",
        PickerInputMode::Path => "path",
    };
    let root_mode = match state.root_mode {
        PickerRootMode::Project => "project",
        PickerRootMode::Filesystem => "filesystem",
    };
    let launcher = match state.launcher_mode {
        PickerLauncherMode::LocalBrowser => "local-browser",
        PickerLauncherMode::ZellijNative => "zellij-native",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("project: ", Style::default().fg(Color::Cyan)),
            Span::raw(state.active_project.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("root:    ", Style::default().fg(Color::Cyan)),
            Span::raw(root_mode),
            Span::raw("   "),
            Span::styled("scope: ", Style::default().fg(Color::Yellow)),
            Span::raw(state.root_dir().display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("cwd:     ", Style::default().fg(Color::Cyan)),
            Span::raw(relative_or_full(&state.active_project, state.display_dir())),
        ]),
        Line::from(vec![
            Span::styled("launch:  ", Style::default().fg(Color::Cyan)),
            Span::raw(launcher),
        ]),
        Line::from(format!(
            "mode:    {mode}   filter: {}",
            if state.browser_filter().is_empty() {
                "<none>".to_string()
            } else {
                state.browser_filter().to_string()
            }
        )),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Reverse Picker")
        .border_style(Style::default().fg(Color::Blue));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_entries(f: &mut Frame<'_>, area: Rect, state: &ReversePickerState) {
    let items = if state.entries.is_empty() {
        vec![ListItem::new(Line::from(
            "  <empty> | 按 / 过滤，Backspace/h 回上级，或把样本放进 binaries/",
        ))]
    } else {
        state
            .entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                let label_style = if entry.is_dir {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:>3} ", idx + 1),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(entry.label.clone(), label_style),
                    Span::raw("  "),
                    Span::styled(entry.detail.clone(), Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(if state.launcher_mode == PickerLauncherMode::ZellijNative {
            "Targets / Fallback Browser"
        } else {
            "Targets"
        })
        .border_style(Style::default().fg(Color::Blue));
    let list = List::new(items)
        .block(block)
        .highlight_symbol(">> ")
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );
    let mut list_state = ListState::default();
    if !state.entries.is_empty() {
        list_state.select(Some(state.selected));
    }
    f.render_stateful_widget(list, area, &mut list_state);
}

fn draw_footer(f: &mut Frame<'_>, area: Rect, state: &ReversePickerState) {
    let path_value = if matches!(state.input_mode, PickerInputMode::Path) {
        let available = area.width.saturating_sub(2 + 6);
        trim_to_tail(&state.path_input, available as usize)
    } else {
        "<off>".to_string()
    };
    let selected_label = state
        .selected_file_path()
        .map(|path| relative_or_full(&state.active_project, &path))
        .unwrap_or_else(|| "<dir>".to_string());
    let action_line = if state.launcher_mode == PickerLauncherMode::ZellijNative {
        "Enter=act on selected  Alt+f=filepicker  p=close panel  o=open only  f=full  i=index  a=analyze"
    } else {
        "Enter=import+index+viewer  o=open only  f=full  i=index  a=analyze"
    };
    let nav_line = if state.launcher_mode == PickerLauncherMode::ZellijNative {
        "j/k=move  h=parent  r=refresh  R=project/fs root  b=local  Z=native  Esc/q=quit"
    } else {
        "j/k=move  h=parent  g/G=top/bottom  r=refresh  R=project/fs root  Esc/q=quit"
    };
    let hint_line = if state.launcher_mode == PickerLauncherMode::ZellijNative {
        "popup 里复用 Strider 键位: arrows/jk move  Tab/Right choose path  Enter confirm path  Backspace up  Ctrl-e hidden"
    } else {
        "直接键入=过滤  /进入过滤  F2|:=path  Alt+f=zellij filepicker  p=close panel  Tab=filepicker(path mode)"
    };
    let lines = vec![
        Line::from(action_line),
        Line::from(nav_line),
        Line::from(hint_line),
        Line::from(vec![
            Span::styled("selected: ", Style::default().fg(Color::Green)),
            Span::raw(selected_label),
        ]),
        Line::from(vec![
            Span::styled("path: ", Style::default().fg(Color::Cyan)),
            Span::raw(path_value),
        ]),
        Line::from(vec![
            Span::styled("resp: ", Style::default().fg(Color::Yellow)),
            Span::raw(if matches!(state.input_mode, PickerInputMode::Path) {
                state.path_status.clone()
            } else {
                state.message.clone()
            }),
        ]),
    ];
    let title = match state.input_mode {
        PickerInputMode::Browse => "Actions",
        PickerInputMode::Filter => "Filter Input",
        PickerInputMode::Path => "Path Input",
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(Color::Blue));
    f.render_widget(Paragraph::new(lines).block(block), area);
    if matches!(state.input_mode, PickerInputMode::Path) {
        let content_x = area.x.saturating_add(1);
        let content_y = area.y.saturating_add(1);
        let path_prefix = 6u16;
        let available = area.width.saturating_sub(2 + path_prefix);
        let cursor_offset = state.path_input.chars().count().min(available as usize) as u16;
        let max_x = area.x.saturating_add(area.width.saturating_sub(2));
        let cursor_x = content_x
            .saturating_add(path_prefix)
            .saturating_add(cursor_offset)
            .min(max_x);
        let cursor_y = content_y.saturating_add(4);
        f.set_cursor(cursor_x, cursor_y);
    }
}

fn trim_to_tail(input: &str, max_chars: usize) -> String {
    if input.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = input.chars().collect();
    if chars.len() <= max_chars {
        return input.to_string();
    }
    chars[chars.len().saturating_sub(max_chars)..]
        .iter()
        .collect()
}
