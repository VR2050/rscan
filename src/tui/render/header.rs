use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::RenderCtx;
use crate::tui::models::InputMode;
use crate::tui::project_store::project_name_from_path;
use crate::tui::view::task_tab_label;

pub(super) fn draw_header(f: &mut Frame<'_>, area: Rect, ctx: &RenderCtx<'_>) {
    let header = Paragraph::new(Line::from(vec![
        Span::styled("rscan TUI ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(
            "1:Dashboard 2:Tasks 3:Launcher 4:Scripts 5:Results 6:Projects  v:console b:layout z:dock p:popup 0:reset [/]:tab j/k:scroll  q:quit  Ctrl-c:quit  r:refresh",
        ),
        Span::raw("  pane="),
        Span::styled(
            ctx.pane.label(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  filter="),
        Span::styled(ctx.filter.label(), Style::default().fg(Color::Yellow)),
        Span::raw("  tab="),
        Span::styled(
            task_tab_label(ctx.task_tab),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  rfilter="),
        Span::styled(
            ctx.result_kind_filter.label(),
            Style::default().fg(Color::LightMagenta),
        ),
        Span::raw("  rsort="),
        Span::styled(
            if ctx.result_failed_first {
                "failed-first"
            } else {
                "created-desc"
            },
            Style::default().fg(Color::LightGreen),
        ),
        Span::raw("  project="),
        Span::styled(
            project_name_from_path(ctx.current_project),
            Style::default().fg(Color::LightCyan),
        ),
        Span::raw(if ctx.script_running {
            "  [script running]"
        } else {
            ""
        }),
        Span::raw(match ctx.input_mode {
            InputMode::Normal => "",
            InputMode::NoteInput => "  [note mode]",
            InputMode::CommandInput => "  [command mode]",
            InputMode::ScriptEdit => "  [script edit mode]",
            InputMode::ScriptNewInput => "  [new script mode]",
            InputMode::ProjectNewInput => "  [new project mode]",
            InputMode::ProjectImportInput => "  [import project mode]",
            InputMode::ProjectCopyInput => "  [copy project mode]",
            InputMode::ProjectRenameInput => "  [rename project mode]",
            InputMode::ResultSearchInput => "  [results search mode]",
        }),
    ]));
    f.render_widget(header, area);
}
