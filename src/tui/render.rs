use std::path::PathBuf;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::Paragraph;

use super::models::{
    InputMode, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectEntry, ProjectTemplate,
    ResultKindFilter, StatusFilter, TaskTab, TaskView,
};

mod header;
mod mini_console;
mod panes;

pub(crate) struct RenderCtx<'a> {
    pub(crate) pane: MainPane,
    pub(crate) filter: StatusFilter,
    pub(crate) task_tab: TaskTab,
    pub(crate) result_kind_filter: ResultKindFilter,
    pub(crate) result_failed_first: bool,
    pub(crate) input_mode: InputMode,
    pub(crate) project_template: ProjectTemplate,
    pub(crate) current_project: &'a PathBuf,
    pub(crate) script_running: bool,

    pub(crate) all_tasks: &'a [TaskView],
    pub(crate) tasks: &'a [TaskView],
    pub(crate) task_selected: usize,
    pub(crate) detail_scroll: u16,
    pub(crate) note_buffer: &'a str,

    pub(crate) launcher_items: &'a [(&'static str, &'static str)],
    pub(crate) launcher_selected: usize,

    pub(crate) scripts: &'a [PathBuf],
    pub(crate) script_selected: usize,
    pub(crate) script_buffer: &'a str,
    pub(crate) script_dirty: bool,
    pub(crate) script_output: &'a [String],

    pub(crate) result_indices: &'a [usize],
    pub(crate) result_selected: usize,
    pub(crate) effect_scroll: u16,
    pub(crate) result_query: &'a str,

    pub(crate) projects: &'a [ProjectEntry],
    pub(crate) project_selected: usize,

    pub(crate) footer_text: &'a str,

    pub(crate) mini_console_visible: bool,
    pub(crate) mini_console_layout: MiniConsoleLayout,
    pub(crate) mini_float_x_pct: u16,
    pub(crate) mini_float_y_pct: u16,
    pub(crate) mini_float_w_pct: u16,
    pub(crate) mini_float_h_pct: u16,
    pub(crate) mini_popup_mode: bool,
    pub(crate) mini_console_tab: MiniConsoleTab,
    pub(crate) mini_console_scroll: u16,
    pub(crate) mini_terminal_lines: &'a [String],
    pub(crate) status_line: &'a str,
}

pub(crate) fn draw_frame(f: &mut Frame<'_>, ctx: &RenderCtx<'_>) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(1),
            ]
            .as_ref(),
        )
        .split(f.size());

    header::draw_header(f, outer[0], ctx);
    panes::draw_active_pane(f, outer[1], ctx);

    let footer = Paragraph::new(ctx.footer_text);
    f.render_widget(footer, outer[2]);

    mini_console::draw_mini_console(f, outer[1], ctx);
}
