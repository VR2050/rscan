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
    let running = ctx
        .all_tasks
        .iter()
        .filter(|t| t.meta.status == crate::cores::engine::task::TaskStatus::Running)
        .count();
    let failed = ctx
        .all_tasks
        .iter()
        .filter(|t| t.meta.status == crate::cores::engine::task::TaskStatus::Failed)
        .count();
    let succeeded = ctx
        .all_tasks
        .iter()
        .filter(|t| t.meta.status == crate::cores::engine::task::TaskStatus::Succeeded)
        .count();
    let spinner = spinner_char(ctx.ui_tick);
    let key_hint = if ctx.zellij_managed {
        " 1-2 panes  :cmd  v aux  q quit"
    } else {
        " 1-2 panes  :cmd  g term  v aux  q quit"
    };
    let line1 = Line::from(vec![
        Span::styled("rscan", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(key_hint),
        Span::raw(" | project="),
        Span::styled(
            project_name_from_path(ctx.current_project),
            Style::default().fg(Color::LightCyan),
        ),
        Span::raw(" | pane="),
        Span::styled(
            ctx.pane.label(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let mut line2 = vec![
        Span::raw("layout="),
        Span::styled(
            ctx.main_layout.label(),
            Style::default().fg(Color::LightYellow),
        ),
        Span::raw(" | queue="),
        Span::styled(
            format!("R{} F{} S{} {}", running, failed, succeeded, spinner),
            Style::default().fg(Color::LightGreen),
        ),
    ];
    if matches!(ctx.pane, crate::tui::models::MainPane::Tasks) {
        line2.push(Span::raw(" | task-filter="));
        line2.push(Span::styled(
            ctx.filter.label(),
            Style::default().fg(Color::Yellow),
        ));
        line2.push(Span::raw(" | task-tab="));
        line2.push(Span::styled(
            task_tab_label(ctx.task_tab),
            Style::default().fg(Color::Green),
        ));
    }
    if matches!(ctx.pane, crate::tui::models::MainPane::Results) {
        line2.push(Span::raw(" | result-filter="));
        line2.push(Span::styled(
            ctx.result_kind_filter.label(),
            Style::default().fg(Color::LightMagenta),
        ));
        line2.push(Span::raw(" | sort="));
        line2.push(Span::styled(
            if ctx.result_failed_first {
                "failed-first"
            } else {
                "created-desc"
            },
            Style::default().fg(Color::LightGreen),
        ));
    }
    if ctx.script_running {
        line2.push(Span::raw(" | script=run"));
    }
    if ctx.zellij_managed {
        line2.push(Span::raw(" | zellij="));
        line2.push(Span::styled(
            ctx.zellij_session.as_deref().unwrap_or("attached"),
            Style::default().fg(Color::LightBlue),
        ));
    }
    let mode = match ctx.input_mode {
        InputMode::Normal => None,
        InputMode::NoteInput => Some("note"),
        InputMode::CommandInput => Some("cmd"),
        InputMode::TerminalInput => Some("terminal"),
        InputMode::ScriptNewInput => Some("script-new"),
        InputMode::ProjectNewInput => Some("proj-new"),
        InputMode::ProjectImportInput => Some("proj-import"),
        InputMode::ProjectCopyInput => Some("proj-copy"),
        InputMode::ProjectRenameInput => Some("proj-rename"),
        InputMode::ResultSearchInput => Some("results-search"),
    };
    if let Some(mode) = mode {
        line2.push(Span::raw(" | mode="));
        line2.push(Span::styled(
            mode,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }

    let header = Paragraph::new(vec![line1, Line::from(line2)]);
    f.render_widget(header, area);
}

fn spinner_char(tick: u64) -> char {
    const SPIN: [char; 4] = ['|', '/', '-', '\\'];
    SPIN[((tick / 2) % 4) as usize]
}
