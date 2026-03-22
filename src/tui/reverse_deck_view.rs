use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::tui::reverse_workbench_support::{canonical_or_clone, relative_or_full, shorten_id};

use super::{DeckDetailMode, ReverseDeckState};

pub(super) fn draw_deck(f: &mut Frame<'_>, state: &ReverseDeckState) {
    let size = f.size();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(5),
        ])
        .split(size);

    let target_label = state
        .selected_target
        .as_ref()
        .map(|path| relative_or_full(&state.active_project, path))
        .unwrap_or_else(|| "<none>".to_string());
    let header = Paragraph::new(Text::from(vec![
        Line::from(vec![
            Span::styled("project: ", Style::default().fg(Color::Yellow)),
            Span::raw(state.active_project.display().to_string()),
        ]),
        Line::from(vec![
            Span::styled("target: ", Style::default().fg(Color::Yellow)),
            if state.selected_target.is_some() {
                Span::styled(
                    target_label,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::raw(target_label)
            },
        ]),
    ]))
    .block(Block::default().title("reverse deck").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    f.render_widget(header, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(rows[1]);

    let jobs_title = if state.selected_target.is_some() {
        format!("Current Target Jobs ({})", state.recent_jobs.len())
    } else {
        format!("Reverse Jobs ({})", state.recent_jobs.len())
    };
    let jobs = List::new(build_jobs_items(state))
        .block(Block::default().title(jobs_title).borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan))
        .highlight_symbol(">> ");
    f.render_stateful_widget(jobs, cols[0], &mut list_state(state.preview_index()));

    let detail_title = match state.detail_mode {
        DeckDetailMode::Logs => format!("Log / Notes ({})", state.log_mode.label()),
        DeckDetailMode::Artifacts => "Artifacts".to_string(),
        DeckDetailMode::Meta => "Meta".to_string(),
    };
    let detail = Paragraph::new(build_detail_text(state))
        .block(Block::default().title(detail_title).borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(detail, cols[1]);

    let footer = Paragraph::new(Text::from(vec![
        Line::from(state.status_line.clone()),
        Line::from("deck: j/k job  Enter target  Tab detail  l log-mode"),
        Line::from(
            "deck: L logs  A arts  W shell  t follow  r refresh  q quit | view h/l 1..6 S d",
        ),
    ]))
    .block(Block::default().title("Bridge").borders(Borders::ALL))
    .wrap(Wrap { trim: false });
    f.render_widget(footer, rows[2]);
}

fn build_jobs_items(state: &ReverseDeckState) -> Vec<ListItem<'static>> {
    if state.recent_jobs.is_empty() {
        return vec![ListItem::new(
            "<none> | 右侧 viewer 发起 full/index 后会回流当前目标的 job。",
        )];
    }
    state
        .recent_jobs
        .iter()
        .map(|job| {
            let target_hit = state
                .selected_target
                .as_ref()
                .map(|target| canonical_or_clone(target) == canonical_or_clone(&job.target))
                .unwrap_or(false);
            let marker = if target_hit { "*" } else { " " };
            ListItem::new(format!(
                "{}{} {:<9} {:<8} {}",
                marker,
                shorten_id(&job.id, 10),
                format!("{:?}", job.status).to_ascii_lowercase(),
                job.mode.as_deref().unwrap_or("-"),
                job.target
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| relative_or_full(&state.active_project, &job.target)),
            ))
        })
        .collect()
}

fn build_detail_text(state: &ReverseDeckState) -> Text<'static> {
    let mut lines = Vec::new();
    if let Some(job) = state.preview_job() {
        let job_mode = job.mode.as_deref().unwrap_or("-").to_string();
        let job_backend = job.backend.clone();
        lines.push(Line::from(vec![
            Span::styled("job: ", Style::default().fg(Color::Yellow)),
            Span::raw(shorten_id(&job.id, 18)),
            Span::raw("  "),
            Span::styled("mode: ", Style::default().fg(Color::Yellow)),
            Span::raw(job_mode),
        ]));
        lines.push(Line::from(vec![
            Span::styled("artifacts: ", Style::default().fg(Color::Yellow)),
            Span::raw(job.artifacts.len().to_string()),
            Span::raw("  "),
            Span::styled("backend: ", Style::default().fg(Color::Yellow)),
            Span::raw(job_backend),
        ]));
        lines.push(Line::from(format!(
            "summary: funcs={} pseudo={} asm={} cfg={} str={} calls={} xrefs={}",
            state.artifact_summary.functions,
            state.artifact_summary.pseudocode_rows,
            state.artifact_summary.asm_rows,
            state.artifact_summary.cfg_rows,
            state.artifact_summary.strings_rows,
            state.artifact_summary.calls_rows,
            state.artifact_summary.xrefs_rows
        )));
        if let Some(recovered) = state.artifact_summary.recovered_prologues {
            lines.push(Line::from(format!(
                "native recovery: recovered_prologues={recovered}"
            )));
        }
        lines.push(Line::from(""));
        match state.detail_mode {
            DeckDetailMode::Logs => {
                for line in &state.log_preview {
                    lines.push(Line::from(line.clone()));
                }
            }
            DeckDetailMode::Artifacts => {
                lines.push(Line::from(format!(
                    "function artifacts: index={} asm={} cfg={} strings={}",
                    state.artifact_summary.functions,
                    state.artifact_summary.asm_rows,
                    state.artifact_summary.cfg_rows,
                    state.artifact_summary.strings_rows
                )));
                lines.push(Line::from(""));
                if job.artifacts.is_empty() {
                    lines.push(Line::from("<none>"));
                } else {
                    for artifact in job.artifacts.iter().take(10) {
                        lines.push(Line::from(artifact.clone()));
                    }
                }
            }
            DeckDetailMode::Meta => {
                lines.push(Line::from(format!(
                    "target: {}",
                    relative_or_full(&state.active_project, &job.target)
                )));
                lines.push(Line::from(format!(
                    "workspace: {}",
                    relative_or_full(&state.active_project, &job.workspace)
                )));
                lines.push(Line::from(format!(
                    "functions/index rows: {}",
                    state.artifact_summary.functions
                )));
                lines.push(Line::from(format!(
                    "pseudocode rows: {}",
                    state.artifact_summary.pseudocode_rows
                )));
                lines.push(Line::from(format!(
                    "status: {}",
                    format!("{:?}", job.status).to_ascii_lowercase()
                )));
                lines.push(Line::from(format!("program: {}", job.program)));
                if let Some(function) = &job.function {
                    lines.push(Line::from(format!("function: {}", function)));
                }
                if !job.note.trim().is_empty() {
                    lines.push(Line::from(format!("note: {}", job.note)));
                }
                if let Some(error) = &job.error {
                    lines.push(Line::from(format!("error: {}", error)));
                }
                lines.push(Line::from(format!("created_at: {}", job.created_at)));
            }
        }
    } else {
        lines.push(Line::from("尚未找到可预览的 reverse job。"));
        lines.push(Line::from(""));
        lines.push(Line::from(
            "按左侧 picker 发起 full/index 后，这里会自动回流。",
        ));
    }
    Text::from(lines)
}

fn list_state(selected: usize) -> ListState {
    let mut state = ListState::default();
    state.select(Some(selected));
    state
}
