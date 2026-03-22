use std::path::PathBuf;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::{ListItem, Paragraph, Row};

use super::models::{
    InputMode, MainLayout, MainPane, MiniConsoleLayout, MiniConsoleTab, ProjectEntry,
    ResultKindFilter, StatusFilter, TaskTab, TaskView,
};

mod header;
mod mini_console;
mod panes;
mod perf;

pub(crate) struct RenderCtx<'a> {
    pub(crate) pane: MainPane,
    pub(crate) main_layout: MainLayout,
    pub(crate) filter: StatusFilter,
    pub(crate) task_tab: TaskTab,
    pub(crate) result_kind_filter: ResultKindFilter,
    pub(crate) result_failed_first: bool,
    pub(crate) input_mode: InputMode,
    pub(crate) current_project: &'a PathBuf,
    pub(crate) script_running: bool,

    pub(crate) all_tasks: &'a [TaskView],
    pub(crate) tasks: &'a [TaskView],
    pub(crate) task_selected: usize,
    pub(crate) detail_scroll: u16,
    pub(crate) task_detail_lines: &'a [Line<'static>],
    pub(crate) task_table_rows: &'a [Row<'static>],
    pub(crate) task_compact_items: &'a [ListItem<'static>],

    pub(crate) launcher_items: &'a [(&'static str, &'static str)],
    pub(crate) launcher_selected: usize,
    pub(crate) launcher_list_items: &'a [ListItem<'static>],
    pub(crate) launcher_detail_lines: &'a [Line<'static>],

    pub(crate) scripts: &'a [PathBuf],
    pub(crate) script_selected: usize,
    pub(crate) script_buffer: &'a str,
    pub(crate) script_dirty: bool,
    pub(crate) script_file_items: &'a [ListItem<'static>],
    pub(crate) script_output_lines: &'a [Line<'static>],

    pub(crate) result_indices: &'a [usize],
    pub(crate) result_selected: usize,
    pub(crate) effect_scroll: u16,
    pub(crate) result_detail_lines: &'a [Line<'static>],
    pub(crate) result_list_items: &'a [ListItem<'static>],

    pub(crate) projects: &'a [ProjectEntry],
    pub(crate) project_selected: usize,
    pub(crate) dashboard_lines: &'a [Line<'static>],
    pub(crate) project_list_items: &'a [ListItem<'static>],
    pub(crate) project_detail_lines: &'a [Line<'static>],

    pub(crate) footer_text: &'a str,
    pub(crate) zellij_managed: bool,
    pub(crate) zellij_session: Option<String>,

    pub(crate) mini_console_visible: bool,
    pub(crate) mini_console_layout: MiniConsoleLayout,
    pub(crate) mini_float_x_pct: u16,
    pub(crate) mini_float_y_pct: u16,
    pub(crate) mini_float_w_pct: u16,
    pub(crate) mini_float_h_pct: u16,
    pub(crate) mini_popup_mode: bool,
    pub(crate) mini_console_tab: MiniConsoleTab,
    pub(crate) mini_console_scroll: u16,
    pub(crate) mini_console_lines: &'a [Line<'static>],
    pub(crate) perf_cpu_pct: Option<f64>,
    pub(crate) perf_mem_used_mb: u64,
    pub(crate) perf_mem_total_mb: u64,
    pub(crate) perf_proc_rss_mb: u64,
    pub(crate) perf_loadavg: &'a str,
    pub(crate) ui_tick: u64,
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
    match ctx.main_layout {
        MainLayout::Single => {
            panes::draw_active_pane(f, outer[1], ctx);
        }
        MainLayout::SplitLeftTasks => {
            if ctx.pane == MainPane::Tasks {
                panes::draw_active_pane(f, outer[1], ctx);
            } else {
                let body = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
                    .split(outer[1]);
                panes::draw_tasks_pane(f, body[0], ctx);
                panes::draw_active_pane(f, body[1], ctx);
            }
        }
        MainLayout::TriPanel => {
            let body = Layout::default()
                .direction(Direction::Horizontal)
                .constraints(
                    [
                        Constraint::Percentage(28),
                        Constraint::Percentage(44),
                        Constraint::Percentage(28),
                    ]
                    .as_ref(),
                )
                .split(outer[1]);
            panes::draw_tasks_pane(f, body[0], ctx);
            panes::draw_active_pane(f, body[1], ctx);
            panes::draw_results_pane(f, body[2], ctx);
        }
    }

    let footer = Paragraph::new(ctx.footer_text);
    f.render_widget(footer, outer[2]);

    perf::draw_perf_panel(f, outer[1], ctx);
    mini_console::draw_mini_console(f, outer[1], ctx);
}
